"""
Egress Control Validation Engine for AgentShield.

Guarantees: AUTHORIZED ACCESS TO DATA DOES NOT AUTOMATICALLY MEAN AUTHORIZATION TO EXPORT THAT DATA.
Validates target destination, tenant/user isolation, data classification, sensitive content, SHA-256 integrity,
provenance, and size limits before information leaves the security boundary.
"""

import time
import re
from typing import List, Optional, Dict, Any, Set, Tuple

from agentshield.context.models import UserIdentity, SecurityDecision, TrustLevel, SourceCategory
from agentshield.security.egress_models import EgressRequest, EgressValidationResult, DestinationCategory
from agentshield.security.secrets import SecretDetector
from agentshield.provenance.lineage import ProvenanceTracker
from agentshield.provenance.models import compute_content_hash
from agentshield.provenance.logger import AuditLogger
from agentshield.policies.engine import PolicyEngine

MAX_EGRESS_SIZE: int = 10000
MAX_BULK_ITEMS: int = 50

DEFAULT_APPROVED_DESTINATIONS: Set[str] = {
    "internal_db",
    "same_tenant_sink",
    "https://api.acme.com/internal",
    "approved_webhook"
}

DEFAULT_BLOCKED_DESTINATIONS: Set[str] = {
    "blocked.com",
    "malicious.org",
    "untrusted_sink",
    "https://leak.badsite.com"
}

class EgressValidator:
    """
    Validates egress requests against destination policies, tenant isolation,
    data security classification, sensitive data protection, SHA-256 integrity, and provenance.
    """

    def __init__(
        self,
        max_egress_size: int = MAX_EGRESS_SIZE,
        max_bulk_items: int = MAX_BULK_ITEMS,
        approved_destinations: Optional[Set[str]] = None,
        blocked_destinations: Optional[Set[str]] = None,
        secret_detector: Optional[SecretDetector] = None,
        audit_logger: Optional[AuditLogger] = None,
        policy_engine: Optional[PolicyEngine] = None
    ):
        self.max_egress_size = max_egress_size
        self.max_bulk_items = max_bulk_items
        self.approved_destinations = approved_destinations if approved_destinations is not None else set(DEFAULT_APPROVED_DESTINATIONS)
        self.blocked_destinations = blocked_destinations if blocked_destinations is not None else set(DEFAULT_BLOCKED_DESTINATIONS)
        self.secret_detector = secret_detector or SecretDetector()
        self.audit_logger = audit_logger or AuditLogger()
        self.policy_engine = policy_engine or PolicyEngine()

    def validate_egress(
        self,
        request: EgressRequest,
        identity: Optional[UserIdentity] = None,
        tracker: Optional[ProvenanceTracker] = None
    ) -> EgressValidationResult:
        """
        Evaluates an EgressRequest against identity, tenant boundaries, destination policy,
        data security classification, secret detection, SHA-256 content hash, and provenance.
        """
        t0 = time.time()
        violations: List[str] = []

        # 1. Identity & Fail-Closed Checks
        target_user = request.user_id
        target_tenant = request.tenant_id

        if not target_user or target_user.strip() == "":
            violations.append("FAIL-CLOSED: Missing or empty user identity in egress request")
            elapsed = (time.time() - t0) * 1000.0
            return EgressValidationResult(
                egress_id=request.egress_id,
                allowed=False,
                decision=SecurityDecision.DENY,
                authorization_valid=False,
                reason="Missing user identity in egress request",
                violations=violations,
                validation_time_ms=elapsed
            )

        if not target_tenant or target_tenant.strip() == "":
            violations.append("FAIL-CLOSED: Missing or empty tenant identity in egress request")
            elapsed = (time.time() - t0) * 1000.0
            return EgressValidationResult(
                egress_id=request.egress_id,
                allowed=False,
                decision=SecurityDecision.DENY,
                authorization_valid=False,
                reason="Missing tenant identity in egress request",
                violations=violations,
                validation_time_ms=elapsed
            )

        if identity is not None:
            if not identity.user_id or not identity.tenant_id:
                violations.append("FAIL-CLOSED: Requesting UserIdentity incomplete")
                elapsed = (time.time() - t0) * 1000.0
                return EgressValidationResult(
                    egress_id=request.egress_id,
                    allowed=False,
                    decision=SecurityDecision.DENY,
                    authorization_valid=False,
                    reason="Incomplete UserIdentity provided",
                    violations=violations,
                    validation_time_ms=elapsed
                )

            if identity.tenant_id != target_tenant:
                violations.append(f"CROSS-TENANT EGRESS DENIED: Request tenant '{identity.tenant_id}' != Target tenant '{target_tenant}'")
                elapsed = (time.time() - t0) * 1000.0
                return EgressValidationResult(
                    egress_id=request.egress_id,
                    allowed=False,
                    decision=SecurityDecision.DENY,
                    authorization_valid=False,
                    reason="Cross-tenant data export prohibited",
                    violations=violations,
                    validation_time_ms=elapsed
                )

            if identity.user_id != target_user and "admin" not in identity.roles:
                violations.append(f"CROSS-USER EGRESS DENIED: Request user '{identity.user_id}' != Target user '{target_user}'")
                elapsed = (time.time() - t0) * 1000.0
                return EgressValidationResult(
                    egress_id=request.egress_id,
                    allowed=False,
                    decision=SecurityDecision.DENY,
                    authorization_valid=False,
                    reason="Cross-user private data export prohibited",
                    violations=violations,
                    validation_time_ms=elapsed
                )

        # 2. Destination Validation & Anti-Spoofing
        destination = request.destination
        if not destination or destination.strip() == "":
            violations.append("MISSING DESTINATION: Egress destination is missing or empty")
            elapsed = (time.time() - t0) * 1000.0
            return EgressValidationResult(
                egress_id=request.egress_id,
                allowed=False,
                decision=SecurityDecision.DENY,
                destination_allowed=False,
                reason="Egress destination is required",
                violations=violations,
                validation_time_ms=elapsed
            )

        # Resolve destination category if unknown
        dest_category = request.destination_category
        if dest_category == DestinationCategory.UNKNOWN_EXTERNAL:
            if destination.startswith("internal"):
                dest_category = DestinationCategory.INTERNAL
            elif destination.startswith("same_tenant"):
                dest_category = DestinationCategory.SAME_TENANT
            elif destination in self.approved_destinations:
                dest_category = DestinationCategory.APPROVED_EXTERNAL

        # Anti-spoofing check
        if destination in self.blocked_destinations or dest_category == DestinationCategory.BLOCKED:
            violations.append(f"BLOCKED DESTINATION: Destination '{destination}' is explicitly blocked by policy")
            elapsed = (time.time() - t0) * 1000.0
            return EgressValidationResult(
                egress_id=request.egress_id,
                allowed=False,
                decision=SecurityDecision.DENY,
                destination_allowed=False,
                reason="Egress to blocked destination denied",
                violations=violations,
                validation_time_ms=elapsed
            )

        is_approved = (
            destination in self.approved_destinations
            or destination.startswith("internal")
            or destination.startswith("same_tenant")
            or dest_category in (DestinationCategory.INTERNAL, DestinationCategory.SAME_TENANT, DestinationCategory.SAME_USER, DestinationCategory.APPROVED_EXTERNAL)
        )

        # 3. Size & Bulk Controls
        if len(request.data) > self.max_egress_size:
            violations.append(f"EGRESS OVERSIZED: Data length {len(request.data)} > limit {self.max_egress_size}")

        if request.item_count > self.max_bulk_items:
            violations.append(f"EXCESSIVE BULK ITEMS: Item count {request.item_count} > limit {self.max_bulk_items}")

        # 4. Content Hash Integrity
        computed_hash = compute_content_hash(request.data)
        integrity_ok = True
        if request.content_hash and request.content_hash != computed_hash:
            integrity_ok = False
            violations.append(f"EGRESS INTEGRITY MISMATCH: Stored hash '{request.content_hash[:8]}...' != Computed hash '{computed_hash[:8]}...'")

        # 5. Provenance Verification
        provenance_ok = True
        if request.provenance_id:
            if tracker and tracker.get_provenance(request.provenance_id) is None:
                provenance_ok = False
                violations.append(f"INVALID PROVENANCE: Provenance ID '{request.provenance_id}' not found in lineage tracker")

        # 6. Secret & Sensitive Data Detection
        sec_res = self.secret_detector.detect_secrets(request.data)
        sensitive_ok = not sec_res["has_secrets"]
        if not sensitive_ok:
            violations.append(f"SENSITIVE DATA DETECTED in egress payload: {sec_res.get('types', [])}")

        # 7. Purpose Validation
        purpose_ok = True
        if dest_category == DestinationCategory.UNKNOWN_EXTERNAL and not is_approved:
            if not request.purpose or request.purpose.strip() == "":
                purpose_ok = False
                violations.append("MISSING EGRESS PURPOSE: External egress request missing required purpose")

        # 8. High Risk Check & Final Security Decision
        is_high_risk = (
            (not is_approved)
            or len(request.data) > self.max_egress_size
            or request.item_count > self.max_bulk_items
            or not sensitive_ok
            or request.trust_level == TrustLevel.UNKNOWN
            or (request.trust_level == TrustLevel.UNTRUSTED and dest_category not in (DestinationCategory.INTERNAL, DestinationCategory.SAME_TENANT, DestinationCategory.SAME_USER, DestinationCategory.APPROVED_EXTERNAL))
        )

        elapsed = (time.time() - t0) * 1000.0

        # Hard failure conditions
        has_hard_failure = (
            not integrity_ok
            or not provenance_ok
            or not sensitive_ok
            or destination in self.blocked_destinations
            or (not is_approved and dest_category == DestinationCategory.BLOCKED)
        )

        if has_hard_failure:
            decision = SecurityDecision.DENY
            allowed = False
            reason = violations[0] if violations else "Egress validation hard security failure"
        elif not is_approved or is_high_risk:
            decision = SecurityDecision.REVIEW
            allowed = False
            reason = "High-risk external egress requires human review"
        else:
            decision = SecurityDecision.ALLOW
            allowed = True
            reason = "Egress request authorized and validated"

        res = EgressValidationResult(
            egress_id=request.egress_id,
            allowed=allowed,
            decision=decision,
            reason=reason,
            violations=violations,
            sensitive_data_detected=not sensitive_ok,
            destination_allowed=is_approved,
            authorization_valid=True,
            provenance_valid=provenance_ok,
            integrity_valid=integrity_ok,
            trust_valid=request.trust_level != TrustLevel.UNKNOWN,
            is_high_risk=is_high_risk,
            validation_time_ms=elapsed
        )

        # Audit logging (never log raw secrets, credentials, or full private data)
        self.audit_logger.log_event(
            "EGRESS_ALLOWED" if allowed else ("EGRESS_REVIEW" if decision == SecurityDecision.REVIEW else "EGRESS_BLOCKED"),
            {
                "egress_id": request.egress_id,
                "user_id": target_user,
                "agent_id": request.agent_id,
                "destination": destination,
                "destination_category": dest_category.value,
                "decision": decision.value,
                "reason": res.reason,
                "provenance_id": request.provenance_id
            },
            tenant_id=target_tenant
        )

        return res
