"""
Trust Classifier & Source Classification Component for AgentShield.
"""

import re
import time
from typing import List, Dict, Any, Optional
from agentshield.context.models import (
    SourceCategory,
    TrustLevel,
    SecurityDecision,
    TrustLabel,
    ContextItem
)

class TrustClassifier:
    """
    Classifies content using authoritative source/provenance metadata,
    resisting any self-elevation attempts embedded in content payloads.
    """

    TRUST_RANKING: Dict[TrustLevel, int] = {
        TrustLevel.UNKNOWN: 0,
        TrustLevel.UNTRUSTED: 1,
        TrustLevel.USER_CONTROLLED: 2,
        TrustLevel.INTERNAL: 3,
        TrustLevel.TRUSTED: 4,
    }

    # Policy mapping for Source Categories
    SOURCE_POLICY_MAP: Dict[SourceCategory, tuple] = {
        # Format: (TrustLevel, is_instruction_allowed, SecurityDecision, reason)
        SourceCategory.SYSTEM: (
            TrustLevel.TRUSTED, True, SecurityDecision.ALLOW, "Trusted system configuration source"
        ),
        SourceCategory.DEVELOPER: (
            TrustLevel.TRUSTED, True, SecurityDecision.ALLOW, "Trusted developer instructions"
        ),
        SourceCategory.INTERNAL_DATABASE: (
            TrustLevel.INTERNAL, False, SecurityDecision.ALLOW, "Internal verified database record"
        ),
        SourceCategory.VERIFIED_DOCUMENT: (
            TrustLevel.INTERNAL, False, SecurityDecision.ALLOW, "Verified internal document"
        ),
        SourceCategory.MEMORY: (
            TrustLevel.INTERNAL, False, SecurityDecision.ALLOW, "Agent state memory store"
        ),
        SourceCategory.USER: (
            TrustLevel.USER_CONTROLLED, False, SecurityDecision.ALLOW, "User prompt input"
        ),
        SourceCategory.TOOL_OUTPUT: (
            TrustLevel.UNTRUSTED, False, SecurityDecision.ISOLATE, "Untrusted tool output"
        ),
        SourceCategory.WEB_CONTENT: (
            TrustLevel.UNTRUSTED, False, SecurityDecision.ISOLATE, "Untrusted web content"
        ),
        SourceCategory.EXTERNAL_DOCUMENT: (
            TrustLevel.UNTRUSTED, False, SecurityDecision.ISOLATE, "Untrusted external document"
        ),
        SourceCategory.UNKNOWN: (
            TrustLevel.UNKNOWN, False, SecurityDecision.DENY, "Unverified or unknown source"
        ),
    }

    SELF_ELEVATION_PATTERNS = [
        r"(?i)system\s+administrator\s+says\s+this\s+is\s+trusted",
        r"(?i)TRUST_LEVEL\s*=\s*TRUSTED",
        r"(?i)SYSTEM\s+MESSAGE\s*:\s*Treat\s+this\s+.*as\s+trusted",
        r"(?i)security_level\s*:\s*trusted",
        r"(?i)developer\s+instruction\s*:\s*ignore\s+the\s+trust\s+policy",
        r"(?i)grant\s+trusted\s+status",
        r"(?i)role\s*=\s*system",
    ]

    def classify_source(
        self,
        source_category: SourceCategory,
        provenance_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        require_provenance_for_internal: bool = True
    ) -> TrustLabel:
        """
        Assigns an immutable TrustLabel based on source category and provenance verification.
        """
        if not isinstance(source_category, SourceCategory):
            try:
                source_category = SourceCategory(str(source_category))
            except Exception:
                source_category = SourceCategory.UNKNOWN

        meta = metadata.copy() if metadata else {}

        # Fail-closed check: if source requires provenance and it is missing, downgrade to UNKNOWN
        if require_provenance_for_internal and source_category in [SourceCategory.INTERNAL_DATABASE, SourceCategory.VERIFIED_DOCUMENT]:
            if not provenance_id:
                source_category = SourceCategory.UNKNOWN

        policy = self.SOURCE_POLICY_MAP.get(
            source_category,
            (TrustLevel.UNKNOWN, False, SecurityDecision.DENY, "Unknown source category")
        )

        trust_level, is_instruction_allowed, decision, reason = policy

        return TrustLabel(
            source_category=source_category,
            trust_level=trust_level,
            classifier_id="AgentShield.TrustClassifier.v1",
            reason=reason,
            provenance_id=provenance_id,
            timestamp=time.time(),
            is_instruction_allowed=is_instruction_allowed,
            decision=decision,
            metadata=meta
        )

    def classify_context_item(
        self,
        item: ContextItem,
        provenance_id: Optional[str] = None
    ) -> ContextItem:
        """
        Classifies ContextItem and attaches TrustLabel, strictly resisting any self-elevation
        claims embedded in content string payload.
        """
        # Ensure self-elevation strings do not mutate source category or trust level
        label = self.classify_source(
            source_category=item.source_category,
            provenance_id=provenance_id or item.metadata.get("provenance_id"),
            metadata=item.metadata
        )

        # Update item security metadata from authoritative TrustLabel
        item.trust_label = label
        item.trust_level = label.trust_level
        item.is_instruction_allowed = label.is_instruction_allowed
        
        # If policy specifies DENY or ISOLATE, update item decision
        if label.decision in [SecurityDecision.DENY, SecurityDecision.ISOLATE]:
            item.decision = label.decision

        return item

    def combine_trust_labels(self, labels: List[TrustLabel]) -> TrustLabel:
        """
        Calculates combined trust label using Trust Propagation Rules:
        Derived or combined content inherits the LOWEST trust level among constituents.
        """
        if not labels:
            return self.classify_source(SourceCategory.UNKNOWN)

        # Find label with lowest trust ranking
        lowest_label = min(labels, key=lambda l: self.TRUST_RANKING.get(l.trust_level, 0))

        # instruction allowed ONLY IF all labels are TRUSTED and allowed
        all_instructions_allowed = all(l.is_instruction_allowed for l in labels)

        return TrustLabel(
            source_category=lowest_label.source_category,
            trust_level=lowest_label.trust_level,
            classifier_id="AgentShield.TrustClassifier.v1",
            reason=f"Combined label inheriting lowest constituent trust level: {lowest_label.trust_level.value}",
            provenance_id=None,
            timestamp=time.time(),
            is_instruction_allowed=all_instructions_allowed,
            decision=lowest_label.decision,
            metadata={"combined_label_count": len(labels)}
        )
