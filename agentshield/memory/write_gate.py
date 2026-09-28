"""
Memory Write Gate for AgentShield.

Enforces security controls governing what information is allowed to be written into agent memory:
UNTRUSTED OR UNAUTHORIZED CONTENT MUST NOT SILENTLY BECOME PERSISTENT MEMORY.
"""

import time
from typing import Optional, List, Dict, Any, Tuple

from agentshield.context.models import (
    UserIdentity,
    ContextItem,
    InstructionType,
    SourceCategory,
    TrustLevel,
    SecurityDecision
)
from agentshield.context.trust_classifier import TrustClassifier
from agentshield.context.integrity import ContextIntegrityEngine
from agentshield.security.injection import PromptInjectionScanner
from agentshield.security.secrets import SecretDetector
from agentshield.provenance.lineage import ProvenanceTracker
from agentshield.provenance.models import compute_content_hash
from agentshield.provenance.logger import AuditLogger
from agentshield.memory.models import MemoryRecord, MemoryWriteRequest, MemoryWriteResult
from agentshield.memory.store import SafeMemoryStore

MAX_MEMORY_SIZE: int = 10000

class MemoryWriteGate:
    """
    Security gate for memory write operations.
    Validates candidate memory against identity, tenant/user isolation, source provenance,
    trust policies, prompt injection scanners, secret detectors, context integrity, and size limits
    BEFORE persisting into SafeMemoryStore.
    """

    def __init__(
        self,
        max_memory_size: int = MAX_MEMORY_SIZE,
        classifier: Optional[TrustClassifier] = None,
        integrity_engine: Optional[ContextIntegrityEngine] = None,
        injection_scanner: Optional[PromptInjectionScanner] = None,
        secret_detector: Optional[SecretDetector] = None,
        audit_logger: Optional[AuditLogger] = None
    ):
        self.max_memory_size = max_memory_size
        self.classifier = classifier or TrustClassifier()
        self.integrity_engine = integrity_engine or ContextIntegrityEngine()
        self.injection_scanner = injection_scanner or PromptInjectionScanner()
        self.secret_detector = secret_detector or SecretDetector()
        self.audit_logger = audit_logger or AuditLogger()

    def evaluate_write_request(
        self,
        request: MemoryWriteRequest,
        identity: Optional[UserIdentity] = None,
        tracker: Optional[ProvenanceTracker] = None,
        store: Optional[SafeMemoryStore] = None
    ) -> MemoryWriteResult:
        """
        Evaluates a MemoryWriteRequest across all Phase 10 security invariants.
        Returns a structured MemoryWriteResult without persisting if unauthorized or invalid.
        """
        violations: List[str] = []

        # 1. Identity & Fail-Closed Checks
        target_user = request.user_id
        target_tenant = request.tenant_id

        if not target_user or target_user.strip() == "":
            violations.append("FAIL-CLOSED: Missing or empty user identity in write request")
            return MemoryWriteResult(
                allowed=False,
                decision=SecurityDecision.DENY,
                reason="Missing user identity in write request",
                violations=violations
            )

        if not target_tenant or target_tenant.strip() == "":
            violations.append("FAIL-CLOSED: Missing or empty tenant identity in write request")
            return MemoryWriteResult(
                allowed=False,
                decision=SecurityDecision.DENY,
                reason="Missing tenant identity in write request",
                violations=violations
            )

        # Identity cross-user & cross-tenant checks if identity provided
        if identity is not None:
            if not identity.user_id or not identity.tenant_id:
                violations.append("FAIL-CLOSED: Requesting UserIdentity incomplete")
                return MemoryWriteResult(
                    allowed=False,
                    decision=SecurityDecision.DENY,
                    reason="Incomplete UserIdentity provided",
                    violations=violations
                )

            if identity.tenant_id != target_tenant:
                violations.append(f"CROSS-TENANT WRITE DENIED: Request tenant '{identity.tenant_id}' != Target tenant '{target_tenant}'")
                return MemoryWriteResult(
                    allowed=False,
                    decision=SecurityDecision.DENY,
                    reason="Cross-tenant memory write prohibited",
                    violations=violations
                )

            if identity.user_id != target_user and "admin" not in identity.roles:
                violations.append(f"CROSS-USER WRITE DENIED: Request user '{identity.user_id}' != Target user '{target_user}'")
                return MemoryWriteResult(
                    allowed=False,
                    decision=SecurityDecision.DENY,
                    reason="Cross-user memory write prohibited",
                    violations=violations
                )

        # 2. Resource & Size Control
        if len(request.content) > self.max_memory_size:
            violations.append(f"MEMORY OVERSIZED: Content length {len(request.content)} > limit {self.max_memory_size}")
            return MemoryWriteResult(
                allowed=False,
                decision=SecurityDecision.DENY,
                reason=f"Memory payload exceeds maximum allowed size ({self.max_memory_size} chars)",
                violations=violations
            )

        # 3. Expiration Check
        if request.expires_at is not None and time.time() > request.expires_at:
            violations.append("EXPIRED MEMORY WRITE: Candidate memory expiration timestamp is in the past")
            return MemoryWriteResult(
                allowed=False,
                decision=SecurityDecision.DENY,
                reason="Cannot write expired memory record",
                violations=violations
            )

        # 4. Provenance Validation
        external_categories = [
            SourceCategory.INTERNAL_DATABASE,
            SourceCategory.VERIFIED_DOCUMENT,
            SourceCategory.WEB_CONTENT,
            SourceCategory.EXTERNAL_DOCUMENT,
            SourceCategory.TOOL_OUTPUT
        ]
        if request.source_category in external_categories or request.provenance_id is not None:
            if not request.provenance_id:
                violations.append("MISSING PROVENANCE: External source category requires valid provenance_id")
                return MemoryWriteResult(
                    allowed=False,
                    decision=SecurityDecision.DENY,
                    reason="External source memory requires explicit provenance_id",
                    violations=violations
                )
            if tracker and tracker.get_provenance(request.provenance_id) is None:
                violations.append(f"INVALID PROVENANCE: Provenance ID '{request.provenance_id}' not found in lineage tracker")
                return MemoryWriteResult(
                    allowed=False,
                    decision=SecurityDecision.DENY,
                    reason="Invalid provenance reference in write candidate",
                    violations=violations
                )

        # 5. Authoritative Trust & Metadata Binding
        # Content payload text cannot modify trust_level, source_category, or permissions
        trust_label = self.classifier.classify_source(
            source_category=request.source_category,
            provenance_id=request.provenance_id
        )

        # Ensure untrusted/external data remains untrusted
        authoritative_trust = TrustLevel.UNTRUSTED
        if request.source_category == SourceCategory.USER:
            authoritative_trust = TrustLevel.USER_CONTROLLED
        elif request.source_category in (SourceCategory.INTERNAL_DATABASE, SourceCategory.VERIFIED_DOCUMENT) and request.provenance_id:
            authoritative_trust = TrustLevel.INTERNAL

        # 6. Sensitive Data / Secret Detection
        sec_res = self.secret_detector.detect_secrets(request.content)
        if sec_res["has_secrets"]:
            violations.append(f"SENSITIVE DATA DETECTED: {sec_res.get('types', [])}")
            return MemoryWriteResult(
                allowed=False,
                decision=SecurityDecision.DENY,
                reason="Memory candidate contains unredacted secrets or credentials",
                violations=violations
            )

        # 7. Prompt Injection Scanning
        inj_res = self.injection_scanner.scan(request.content)
        if inj_res["is_injection"]:
            violations.append(f"PROMPT INJECTION DETECTED in write payload: {inj_res.get('matched_patterns', [])}")
            return MemoryWriteResult(
                allowed=True,  # Allowed to persist only in ISOLATED state if policy permits, otherwise DENY
                decision=SecurityDecision.ISOLATE,
                reason="Prompt injection payload detected in write candidate",
                trust_level=TrustLevel.UNTRUSTED,
                violations=violations
            )

        # 8. Content Hash & Context Integrity Check
        content_hash = compute_content_hash(request.content)
        candidate_item = ContextItem(
            content=request.content,
            raw_content=request.content,
            instruction_type=InstructionType.MEMORY,
            source_category=request.source_category,
            trust_level=authoritative_trust,
            origin=f"write_candidate:{request.user_id}",
            provenance_id=request.provenance_id,
            content_hash=content_hash,
            is_instruction_allowed=False,
            metadata=request.metadata.copy()
        )

        integrity_res = self.integrity_engine.validate_context([candidate_item], tracker=tracker)
        if not integrity_res.valid:
            violations.extend(integrity_res.violations)
            return MemoryWriteResult(
                allowed=False,
                decision=SecurityDecision.DENY,
                reason="Write candidate failed Context Integrity validation",
                violations=violations
            )

        # 9. Duplicate / Conflict Check if store provided
        write_decision = SecurityDecision.ALLOW
        reason = "Memory write request authorized and validated"

        if store:
            # Check duplicate hash or conflicting record
            existing = store._records.values()
            for rec in existing:
                if rec.tenant_id == target_tenant and rec.owner_id == target_user:
                    if rec.content_hash == content_hash:
                        write_decision = SecurityDecision.REVIEW
                        violations.append(f"DUPLICATE MEMORY: Identical memory content already exists ({rec.memory_id})")
                        reason = "Duplicate memory record detected"
                        break

        # Create candidate MemoryRecord
        record = MemoryRecord(
            memory_id=request.key or request.metadata.get("memory_id") or undefined_id(),
            owner_id=target_user,
            tenant_id=target_tenant,
            content=request.content,
            source_category=request.source_category,
            trust_level=authoritative_trust,
            provenance_id=request.provenance_id,
            content_hash=content_hash,
            created_at=request.timestamp,
            expires_at=request.expires_at,
            metadata=request.metadata.copy()
        )

        return MemoryWriteResult(
            allowed=True,
            decision=write_decision,
            reason=reason,
            violations=violations,
            memory_id=record.memory_id,
            provenance_id=request.provenance_id,
            trust_level=authoritative_trust,
            content_hash=content_hash,
            integrity_valid=True,
            record=record
        )

    def execute_memory_write(
        self,
        request: MemoryWriteRequest,
        identity: Optional[UserIdentity] = None,
        tracker: Optional[ProvenanceTracker] = None,
        store: Optional[SafeMemoryStore] = None
    ) -> MemoryWriteResult:
        """
        Evaluates a MemoryWriteRequest and, if allowed, persists the record into SafeMemoryStore.
        Audit logs the operation without exposing raw sensitive content.
        """
        res = self.evaluate_write_request(request, identity=identity, tracker=tracker, store=store)

        target_tenant = request.tenant_id or (identity.tenant_id if identity else "unknown")
        target_user = request.user_id or (identity.user_id if identity else "unknown")

        if not res.allowed or res.decision == SecurityDecision.DENY:
            self.audit_logger.log_event(
                "MEMORY_WRITE_BLOCKED",
                {
                    "user_id": target_user,
                    "decision": res.decision.value,
                    "reason": res.reason,
                    "violations": res.violations,
                    "provenance_id": request.provenance_id,
                    "source_category": request.source_category.value
                },
                tenant_id=target_tenant
            )
            return res

        # Persist if store provided and decision is not DENY
        if store and res.record:
            store.set_record(res.record)

        self.audit_logger.log_event(
            "MEMORY_WRITE_ALLOWED",
            {
                "memory_id": res.memory_id,
                "user_id": target_user,
                "decision": res.decision.value,
                "reason": res.reason,
                "provenance_id": res.provenance_id,
                "trust_level": res.trust_level.value,
                "content_hash": res.content_hash
            },
            tenant_id=target_tenant
        )

        return res

def undefined_id() -> str:
    import uuid
    return str(uuid.uuid4())
