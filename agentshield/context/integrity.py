"""
Context Integrity Engine Module for AgentShield.
"""

import re
import time
from typing import List, Dict, Any, Optional, Tuple
from agentshield.context.models import (
    ContextItem,
    SourceCategory,
    TrustLevel,
    SecurityDecision,
    IntegrityStatus,
    ContextIntegrityResult
)
from agentshield.provenance.models import compute_content_hash
from agentshield.provenance.lineage import ProvenanceTracker

class ContextIntegrityEngine:
    """
    Validates context items before downstream agent execution, enforcing 8 security invariants:
    
    INVARIANT 1: UNTRUSTED content cannot become TRUSTED based on content claims.
    INVARIANT 2: UNTRUSTED content cannot gain instruction privileges.
    INVARIANT 3: Valid content hash does not elevate trust.
    INVARIANT 4: Valid provenance does not automatically elevate trust.
    INVARIANT 5: Agent-generated content does not automatically become TRUSTED.
    INVARIANT 6: Derived context items must retain source provenance parent IDs.
    INVARIANT 7: Unauthorized metadata modifications are detected.
    INVARIANT 8: Missing or invalid security metadata fails safely to DENY.
    """

    TAMPERING_PATTERNS = [
        r"(?i)trust_level\s*=\s*TRUSTED",
        r"(?i)SOURCE\s*=\s*SYSTEM",
        r"(?i)can_instruct_agent\s*=\s*true",
        r"(?i)is_instruction_allowed\s*=\s*true",
        r"(?i)security_decision\s*=\s*ALLOW",
    ]

    def validate_item(
        self,
        item: ContextItem,
        tracker: Optional[ProvenanceTracker] = None
    ) -> Tuple[bool, List[str], Dict[str, bool]]:
        """
        Validates a single ContextItem against all 8 security invariants.
        Returns (is_valid, list_of_violations, component_statuses).
        """
        violations: List[str] = []
        status_flags = {
            "provenance_valid": True,
            "hash_valid": True,
            "trust_valid": True,
            "instruction_boundary_valid": True
        }

        # INVARIANT 2: UNTRUSTED or USER_CONTROLLED content cannot have instruction privileges
        if item.trust_level in [TrustLevel.UNTRUSTED, TrustLevel.USER_CONTROLLED, TrustLevel.UNKNOWN]:
            if item.is_instruction_allowed:
                violations.append("INVARIANT 2 VIOLATION: Untrusted or user-controlled content cannot gain instruction privileges")
                status_flags["instruction_boundary_valid"] = False

        # INVARIANT 1: External/untrusted sources cannot become TRUSTED
        if item.source_category in [SourceCategory.WEB_CONTENT, SourceCategory.EXTERNAL_DOCUMENT, SourceCategory.TOOL_OUTPUT]:
            if item.trust_level == TrustLevel.TRUSTED:
                violations.append("INVARIANT 1 VIOLATION: External/untrusted source category cannot become TRUSTED")
                status_flags["trust_valid"] = False

        # INVARIANT 5: Derived or Agent-generated content cannot automatically become TRUSTED
        if item.metadata.get("is_derived") or item.metadata.get("parent_provenance_ids"):
            if item.trust_level == TrustLevel.TRUSTED and item.source_category not in [SourceCategory.SYSTEM, SourceCategory.DEVELOPER]:
                violations.append("INVARIANT 5 VIOLATION: Agent-generated or derived content cannot automatically become TRUSTED")
                status_flags["trust_valid"] = False

        # INVARIANT 6: Derived context items must retain references to parent provenance IDs
        if item.metadata.get("is_derived") and not item.metadata.get("parent_provenance_ids"):
            violations.append("INVARIANT 6 VIOLATION: Derived context item missing required parent provenance references")
            status_flags["provenance_valid"] = False

        # INVARIANT 7: Detect metadata tampering inside content string
        content_tamper = any(re.search(pat, item.content or "") for pat in self.TAMPERING_PATTERNS)
        if content_tamper:
            if item.trust_level == TrustLevel.TRUSTED and item.source_category not in [SourceCategory.SYSTEM, SourceCategory.DEVELOPER]:
                violations.append("INVARIANT 7 VIOLATION: Unauthorized security metadata elevation attempt detected in payload")
                status_flags["trust_valid"] = False

        # INVARIANT 3 & Hash Check: Verify SHA-256 fingerprint
        if item.content_hash:
            computed = compute_content_hash(item.raw_content)
            if computed != item.content_hash:
                violations.append(f"CONTENT HASH MISMATCH: SHA-256 fingerprint changed (stored: {item.content_hash[:8]}..., computed: {computed[:8]}...)")
                status_flags["hash_valid"] = False

        # SHA-256 Tracker Integrity Check
        if tracker and item.provenance_id:
            integ_res = tracker.verify_integrity(item.provenance_id, item.raw_content)
            if not integ_res.get("valid", True):
                violations.append(f"PROVENANCE INTEGRITY VIOLATION: {integ_res.get('reason')}")
                status_flags["provenance_valid"] = False

        # INVARIANT 8: Missing required provenance for internal data
        if item.trust_level == TrustLevel.INTERNAL or item.source_category in [SourceCategory.INTERNAL_DATABASE, SourceCategory.VERIFIED_DOCUMENT]:
            if not item.provenance_id:
                violations.append("INVARIANT 8 VIOLATION: Missing required provenance_id for internal context item")
                status_flags["provenance_valid"] = False

        # INVARIANT 8: Missing or UNKNOWN trust level must fail safe
        if item.trust_level == TrustLevel.UNKNOWN or item.source_category == SourceCategory.UNKNOWN:
            violations.append("INVARIANT 8 VIOLATION: Unknown trust level or source category must fail closed")
            status_flags["trust_valid"] = False

        is_valid = len(violations) == 0
        return is_valid, violations, status_flags

    def validate_context(
        self,
        items: List[ContextItem],
        tracker: Optional[ProvenanceTracker] = None
    ) -> ContextIntegrityResult:
        """
        Validates a collection of context items before downstream agent execution,
        returning a comprehensive ContextIntegrityResult and performance metrics.
        """
        t0 = time.time()
        all_violations: List[str] = []
        provenance_ok = True
        hash_ok = True
        trust_ok = True
        boundary_ok = True

        for item in items:
            valid, violations, flags = self.validate_item(item, tracker=tracker)
            if not valid:
                all_violations.extend(violations)
                if not flags["provenance_valid"]:
                    provenance_ok = False
                if not flags["hash_valid"]:
                    hash_ok = False
                if not flags["trust_valid"]:
                    trust_ok = False
                if not flags["instruction_boundary_valid"]:
                    boundary_ok = False

        t1 = time.time()
        duration_ms = (t1 - t0) * 1000.0

        is_context_valid = len(all_violations) == 0

        if is_context_valid:
            status = IntegrityStatus.VALID
            decision = SecurityDecision.ALLOW
            reason = "Context integrity verified cleanly across all items"
        else:
            status = IntegrityStatus.INVALID
            decision = SecurityDecision.DENY
            reason = f"Context integrity failure: {len(all_violations)} violation(s) detected"

        return ContextIntegrityResult(
            valid=is_context_valid,
            integrity_status=status,
            violations=all_violations,
            provenance_valid=provenance_ok,
            hash_valid=hash_ok,
            trust_valid=trust_ok,
            instruction_boundary_valid=boundary_ok,
            security_decision=decision,
            reason=reason,
            validation_time_ms=round(duration_ms, 4),
            item_count=len(items)
        )
