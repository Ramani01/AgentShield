"""
Token / Data Audience Validation Engine for AgentShield.

Guarantees: AUTHORIZED ACCESS TO DATA DOES NOT AUTOMATICALLY MEAN AUTHORIZATION TO DISCLOSE THAT DATA TO EVERY AUDIENCE.
Evaluates subject identity, token context, tenant/user scopes, audience claims, and audience propagation rules.
"""

import time
import re
from typing import List, Optional, Dict, Any, Tuple

from agentshield.context.models import UserIdentity, SecurityDecision, TrustLevel
from agentshield.security.audience_models import (
    AudienceType,
    AudienceClaim,
    AudiencePolicy,
    SecurityTokenContext,
    AudienceValidationResult
)
from agentshield.provenance.lineage import ProvenanceTracker
from agentshield.provenance.logger import AuditLogger
from agentshield.policies.engine import PolicyEngine

AUDIENCE_RESTRICTIVENESS: Dict[AudienceType, int] = {
    AudienceType.SPECIFIC_PRINCIPAL: 100,
    AudienceType.SAME_USER: 90,
    AudienceType.SAME_TENANT: 70,
    AudienceType.INTERNAL: 50,
    AudienceType.APPROVED_SERVICE: 40,
    AudienceType.APPROVED_EXTERNAL: 30,
    AudienceType.PUBLIC: 10,
    AudienceType.UNKNOWN: 0,
}

class AudienceValidator:
    """
    Validates data disclosure against subject identity, token contexts, audience claims, and policies.
    Does NOT issue credentials or transmit tokens over external networks.
    """

    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        policy_engine: Optional[PolicyEngine] = None
    ):
        self.audit_logger = audit_logger or AuditLogger()
        self.policy_engine = policy_engine or PolicyEngine()

    def validate_audience(
        self,
        claim: AudienceClaim,
        identity: Optional[UserIdentity] = None,
        token_context: Optional[SecurityTokenContext] = None,
        policy: Optional[AudiencePolicy] = None,
        tracker: Optional[ProvenanceTracker] = None,
        raw_content: Optional[str] = None
    ) -> AudienceValidationResult:
        """
        Evaluates an AudienceClaim against identity, security token context, and audience policy.
        """
        t0 = time.time()
        violations: List[str] = []
        eff_policy = policy or AudiencePolicy()

        # Derive effective identity from token_context if identity is missing
        eff_user = identity.user_id if identity else (token_context.subject_id if token_context else "")
        eff_tenant = identity.tenant_id if identity else (token_context.tenant_id if token_context else "")

        # 1. Identity & Fail-Closed Checks
        if not eff_user or eff_user.strip() == "":
            violations.append("FAIL-CLOSED: Missing or empty user identity for audience evaluation")
            elapsed = (time.time() - t0) * 1000.0
            return AudienceValidationResult(
                valid=False,
                decision=SecurityDecision.DENY,
                reason="Missing user identity in audience request",
                violations=violations,
                audience_type=claim.audience_type,
                validation_time_ms=elapsed
            )

        if not eff_tenant or eff_tenant.strip() == "":
            violations.append("FAIL-CLOSED: Missing or empty tenant identity for audience evaluation")
            elapsed = (time.time() - t0) * 1000.0
            return AudienceValidationResult(
                valid=False,
                decision=SecurityDecision.DENY,
                reason="Missing tenant identity in audience request",
                violations=violations,
                audience_type=claim.audience_type,
                validation_time_ms=elapsed
            )

        # 2. Token Context Checks (if provided)
        token_ok = True
        if token_context:
            if token_context.is_expired():
                token_ok = False
                violations.append("EXPIRED_TOKEN_CONTEXT: SecurityTokenContext expiration timestamp is in the past")

            if token_context.tenant_id != eff_tenant:
                token_ok = False
                violations.append(f"TOKEN_TENANT_MISMATCH: Token tenant '{token_context.tenant_id}' != Request tenant '{eff_tenant}'")

            if claim.tenant_id and token_context.tenant_id != claim.tenant_id:
                token_ok = False
                violations.append(f"TOKEN_TENANT_MISMATCH: Token tenant '{token_context.tenant_id}' != Claim tenant '{claim.tenant_id}'")

            if claim.principal_id and token_context.subject_id != claim.principal_id and "admin" not in getattr(identity, "roles", []):
                token_ok = False
                violations.append(f"TOKEN_AUDIENCE_MISMATCH: Token subject '{token_context.subject_id}' != Claim principal '{claim.principal_id}'")

            if not token_ok:
                elapsed = (time.time() - t0) * 1000.0
                return AudienceValidationResult(
                    valid=False,
                    decision=SecurityDecision.DENY,
                    token_valid=False,
                    reason=violations[0],
                    violations=violations,
                    audience_type=claim.audience_type,
                    validation_time_ms=elapsed
                )

        # 3. Structural Metadata Binding & Anti-Escalation
        # Text in raw_content cannot broaden claim.audience_type
        if raw_content:
            if "audience = PUBLIC" in raw_content or "audience_type = PUBLIC" in raw_content:
                if claim.audience_type != AudienceType.PUBLIC:
                    violations.append("UNAUTHORIZED_AUDIENCE_ESCALATION: Text payload attempted unauthorized audience expansion to PUBLIC")

        # 4. Audience Type Specific Evaluations
        principal_ok = True
        tenant_ok = True
        aud_type = claim.audience_type

        if aud_type == AudienceType.SAME_USER:
            if claim.principal_id and claim.principal_id != eff_user:
                principal_ok = False
                violations.append(f"CROSS_USER_AUDIENCE_MISMATCH: Requester '{eff_user}' != Claim user '{claim.principal_id}'")

        elif aud_type == AudienceType.SAME_TENANT:
            if claim.tenant_id and claim.tenant_id != eff_tenant:
                tenant_ok = False
                violations.append(f"CROSS_TENANT_AUDIENCE_MISMATCH: Requester tenant '{eff_tenant}' != Claim tenant '{claim.tenant_id}'")

        elif aud_type == AudienceType.SPECIFIC_PRINCIPAL:
            if not claim.principal_id or claim.principal_id != eff_user:
                principal_ok = False
                violations.append(f"SPECIFIC_PRINCIPAL_MISMATCH: Requester '{eff_user}' != Required principal '{claim.principal_id}'")

        elif aud_type == AudienceType.PUBLIC:
            if not eff_policy.allow_public:
                violations.append("PUBLIC_DISCLOSURE_DISABLED: Public audience disclosure disabled by AudiencePolicy")

        elif aud_type == AudienceType.UNKNOWN:
            violations.append("UNKNOWN_AUDIENCE: Unknown or unspecified audience claim")

        # Provenance verification if tracker provided
        prov_ok = True
        if claim.provenance_id and tracker:
            if tracker.get_provenance(claim.provenance_id) is None:
                prov_ok = False
                violations.append(f"INVALID PROVENANCE: Provenance ID '{claim.provenance_id}' not found in tracker")

        elapsed = (time.time() - t0) * 1000.0
        final_valid = (len(violations) == 0 and principal_ok and tenant_ok and token_ok and prov_ok)

        decision = SecurityDecision.ALLOW
        if not final_valid:
            if aud_type == AudienceType.UNKNOWN:
                decision = SecurityDecision.REVIEW
            else:
                decision = SecurityDecision.DENY

        res = AudienceValidationResult(
            valid=final_valid,
            decision=decision,
            reason="Audience authorized and validated" if final_valid else violations[0],
            violations=violations,
            audience_type=aud_type,
            principal_valid=principal_ok,
            tenant_valid=tenant_ok,
            token_valid=token_ok,
            validation_time_ms=elapsed
        )

        # Audit logging (never log raw secrets or payload text)
        self.audit_logger.log_event(
            "AUDIENCE_VALIDATED" if final_valid else ("AUDIENCE_REVIEW" if decision == SecurityDecision.REVIEW else "AUDIENCE_BLOCKED"),
            {
                "user_id": eff_user,
                "audience_type": aud_type.value,
                "principal_id": claim.principal_id,
                "decision": decision.value,
                "reason": res.reason
            },
            tenant_id=eff_tenant
        )

        return res

    def propagate_audience(self, parent_claims: List[AudienceClaim]) -> AudienceClaim:
        """
        Determines the effective AudienceClaim for derived or mixed-audience data.
        Enforces conservative lowest-audience / most-restrictive audience propagation.
        """
        if not parent_claims:
            return AudienceClaim(audience_type=AudienceType.UNKNOWN)

        # Find claim with highest restrictiveness score
        most_restrictive = max(parent_claims, key=lambda c: AUDIENCE_RESTRICTIVENESS.get(c.audience_type, 0))

        # Collect parent provenance IDs if present
        p_ids = [c.provenance_id for c in parent_claims if c.provenance_id]

        return AudienceClaim(
            audience_type=most_restrictive.audience_type,
            principal_id=most_restrictive.principal_id,
            tenant_id=most_restrictive.tenant_id,
            provenance_id=p_ids[0] if p_ids else None,
            metadata={"propagated_from_parents": len(parent_claims)}
        )
