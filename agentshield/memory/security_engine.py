"""
Memory Security Engine for AgentShield.

Enforces tenant/user isolation, memory authorization, provenance preservation,
hash integrity, trust classification, prompt injection detection, and context integrity
for memory reading, retrieval, and consumption.
"""

from typing import List, Optional, Dict, Any, Tuple
import time

from agentshield.context.models import (
    UserIdentity,
    ContextItem,
    InstructionType,
    SourceCategory,
    TrustLevel,
    SecurityDecision,
    IntegrityStatus
)
from agentshield.context.boundary import InstructionBoundary
from agentshield.context.trust_classifier import TrustClassifier
from agentshield.context.integrity import ContextIntegrityEngine
from agentshield.security.injection import PromptInjectionScanner
from agentshield.provenance.lineage import ProvenanceTracker
from agentshield.provenance.models import compute_content_hash
from agentshield.policies.engine import PolicyEngine
from agentshield.memory.models import MemoryRecord, MemoryAccessResult

class MemorySecurityEngine:
    """
    Engine responsible for securing memory retrieval, reading, and context integration.
    Guarantees: MEMORY MUST NOT BYPASS THE SECURITY CONTROLS ALREADY APPLIED TO NORMAL CONTEXT.
    """

    def __init__(
        self,
        classifier: Optional[TrustClassifier] = None,
        boundary: Optional[InstructionBoundary] = None,
        integrity_engine: Optional[ContextIntegrityEngine] = None,
        injection_scanner: Optional[PromptInjectionScanner] = None,
        policy_engine: Optional[PolicyEngine] = None
    ):
        self.classifier = classifier or TrustClassifier()
        self.boundary = boundary or InstructionBoundary()
        self.integrity_engine = integrity_engine or ContextIntegrityEngine()
        self.injection_scanner = injection_scanner or PromptInjectionScanner()
        self.policy_engine = policy_engine or PolicyEngine()

    def evaluate_memory_access(
        self,
        identity: Optional[UserIdentity],
        record: MemoryRecord,
        tracker: Optional[ProvenanceTracker] = None,
        is_relevant: bool = True
    ) -> MemoryAccessResult:
        """
        Evaluates a memory record against identity, tenant isolation, authorization,
        integrity, trust, prompt injection, and context integrity controls.
        """
        violations: List[str] = []

        # 1. Identity & Fail-Closed Checks
        if identity is None:
            return MemoryAccessResult(
                memory_id=record.memory_id,
                authorized=False,
                security_decision=SecurityDecision.DENY,
                reason="FAIL-CLOSED: Missing requesting identity",
                violations=["MISSING_USER_IDENTITY"]
            )

        if not identity.user_id or identity.user_id.strip() == "":
            return MemoryAccessResult(
                memory_id=record.memory_id,
                authorized=False,
                security_decision=SecurityDecision.DENY,
                reason="FAIL-CLOSED: User identity is empty or invalid",
                violations=["EMPTY_USER_ID"]
            )

        if not identity.tenant_id or identity.tenant_id.strip() == "":
            return MemoryAccessResult(
                memory_id=record.memory_id,
                authorized=False,
                security_decision=SecurityDecision.DENY,
                reason="FAIL-CLOSED: Tenant identity is empty or invalid",
                violations=["EMPTY_TENANT_ID"]
            )

        # 2. User & Tenant Isolation
        if identity.tenant_id != record.tenant_id:
            violations.append(f"CROSS-TENANT ACCESS DENIED: Identity tenant '{identity.tenant_id}' != Memory tenant '{record.tenant_id}'")
            return MemoryAccessResult(
                memory_id=record.memory_id,
                authorized=False,
                security_decision=SecurityDecision.DENY,
                reason=f"Cross-tenant memory access prohibited ({identity.tenant_id} != {record.tenant_id})",
                violations=violations
            )

        if identity.user_id != record.owner_id and "admin" not in identity.roles:
            violations.append(f"CROSS-USER ACCESS DENIED: Requesting user '{identity.user_id}' != Memory owner '{record.owner_id}'")
            return MemoryAccessResult(
                memory_id=record.memory_id,
                authorized=False,
                security_decision=SecurityDecision.DENY,
                reason=f"Cross-user memory access prohibited ({identity.user_id} != {record.owner_id})",
                violations=violations
            )

        # 3. Expiration and Staleness Checks
        if record.is_expired():
            violations.append("MEMORY EXPIRED: Record has passed its expiration timestamp")
            return MemoryAccessResult(
                memory_id=record.memory_id,
                authorized=False,
                security_decision=SecurityDecision.DENY,
                reason="Memory record is expired",
                violations=violations
            )

        if record.is_stale:
            violations.append("MEMORY STALE: Record is marked as stale")

        # 4. Hash & Tampering Integrity Verification
        computed_hash = compute_content_hash(record.content)
        hash_valid = (record.content_hash == computed_hash)
        if not hash_valid:
            violations.append(f"INTEGRITY VIOLATION: Recorded hash '{record.content_hash}' != Computed hash '{computed_hash}'")
            return MemoryAccessResult(
                memory_id=record.memory_id,
                authorized=False,
                integrity_valid=False,
                security_decision=SecurityDecision.DENY,
                reason="Memory content hash mismatch / tampering detected",
                violations=violations
            )

        # 5. Provenance Verification
        provenance_valid = True
        if record.provenance_id:
            if tracker and tracker.get_provenance(record.provenance_id) is None:
                provenance_valid = False
                violations.append(f"INVALID PROVENANCE: Provenance ID '{record.provenance_id}' not found in lineage tracker")
                return MemoryAccessResult(
                    memory_id=record.memory_id,
                    authorized=False,
                    provenance_valid=False,
                    security_decision=SecurityDecision.DENY,
                    reason="Invalid provenance reference in memory record",
                    violations=violations
                )

        # 6. Trust Classification & Invariant Enforcement
        # Rule: MEMORY MUST NEVER AUTOMATICALLY BECOME TRUSTED OR INSTRUCTION ALLOWED
        trust_label = self.classifier.classify_source(
            source_category=record.source_category,
            provenance_id=record.provenance_id
        )
        
        # Determine authoritative trust for ContextItem
        if not record.provenance_id:
            authoritative_trust = TrustLevel.UNTRUSTED
        else:
            if trust_label.trust_level == TrustLevel.INTERNAL and record.provenance_id:
                authoritative_trust = TrustLevel.INTERNAL
            elif trust_label.trust_level == TrustLevel.USER_CONTROLLED:
                authoritative_trust = TrustLevel.USER_CONTROLLED
            else:
                authoritative_trust = TrustLevel.UNTRUSTED

        is_instruction_allowed = False  # NEVER allow memory to execute as trusted instruction

        # 7. Create ContextItem preserving all security metadata
        context_item = ContextItem(
            content=record.content,
            raw_content=record.content,
            instruction_type=InstructionType.MEMORY,
            source_category=record.source_category,
            trust_level=authoritative_trust,
            origin=f"memory:{record.memory_id}",
            provenance_id=record.provenance_id,
            content_hash=record.content_hash,
            is_instruction_allowed=is_instruction_allowed,
            decision=SecurityDecision.ISOLATE if authoritative_trust in (TrustLevel.UNTRUSTED, TrustLevel.UNKNOWN) else SecurityDecision.ALLOW,
            metadata={
                "memory_id": record.memory_id,
                "owner_id": record.owner_id,
                "tenant_id": record.tenant_id,
                "created_at": record.created_at,
                "is_stale": record.is_stale,
                **record.metadata
            }
        )

        # 8. Prompt Injection Scanning
        injection_res = self.injection_scanner.scan(record.content)
        if injection_res["is_injection"]:
            context_item.decision = SecurityDecision.ISOLATE
            violations.append(f"PROMPT INJECTION DETECTED in memory: {injection_res.get('matched_patterns', [])}")
            return MemoryAccessResult(
                memory_id=record.memory_id,
                authorized=True,  # Access authorized but contained/isolated
                integrity_valid=hash_valid,
                provenance_valid=provenance_valid,
                security_decision=SecurityDecision.ISOLATE,
                reason="Prompt injection payload detected in memory record",
                context_item=context_item,
                violations=violations
            )

        # 9. Context Integrity Engine Validation
        integrity_res = self.integrity_engine.validate_context([context_item], tracker=tracker)
        if not integrity_res.valid:
            violations.extend(integrity_res.violations)
            return MemoryAccessResult(
                memory_id=record.memory_id,
                authorized=False,
                integrity_valid=False,
                security_decision=SecurityDecision.DENY,
                reason="Memory ContextItem failed Context Integrity validation",
                violations=violations
            )

        # Determine final security decision (stale memories evaluate to REVIEW)
        final_decision = SecurityDecision.ALLOW
        if record.is_stale:
            final_decision = SecurityDecision.REVIEW
        elif authoritative_trust in (TrustLevel.UNTRUSTED, TrustLevel.UNKNOWN):
            final_decision = SecurityDecision.ISOLATE

        return MemoryAccessResult(
            memory_id=record.memory_id,
            authorized=True,
            integrity_valid=True,
            provenance_valid=provenance_valid,
            security_decision=final_decision,
            reason="Memory record successfully authorized and validated",
            context_item=context_item,
            violations=violations
        )

    def process_memory_retrieval(
        self,
        identity: Optional[UserIdentity],
        memory_records: List[MemoryRecord],
        tracker: Optional[ProvenanceTracker] = None
    ) -> List[ContextItem]:
        """
        Processes a list of retrieved memory records, returning authorized, safe ContextItems.
        Unauthorized or invalid memories are filtered out.
        """
        valid_items: List[ContextItem] = []

        for record in memory_records:
            eval_res = self.evaluate_memory_access(identity, record, tracker=tracker)
            if eval_res.authorized and eval_res.context_item:
                valid_items.append(eval_res.context_item)

        return valid_items
