"""
Phase 24: Behavior Pattern Analyzer.
Performs canonical sequence normalization, deterministic pattern matching, and risk assessment.
"""

from typing import List, Optional, Tuple
from agentshield.behavior.models import BehaviorSequence, BehaviorEvent, BehaviorAssessment
from agentshield.behavior.patterns import BehaviorPattern, PatternRegistry


class BehaviorPatternAnalyzer:
    """
    Analyzes behavioral event sequences against security pattern registries.
    Determines if a sequence contains suspicious multi-step behavior patterns.
    """

    def __init__(self, registry: Optional[PatternRegistry] = None):
        self.registry = registry or PatternRegistry(include_defaults=True)

    def normalize_sequence(self, sequence: BehaviorSequence) -> str:
        """Returns the canonical string representation of the sequence."""
        return sequence.to_canonical_string()

    def analyze_sequence(self, sequence: BehaviorSequence) -> BehaviorAssessment:
        """
        Analyzes sequence against all active patterns in deterministic order.
        Returns highest risk BehaviorAssessment if pattern matches, else ALLOW assessment.
        """
        if not sequence or not sequence.events:
            return BehaviorAssessment(
                matched=False,
                pattern_id=None,
                pattern_name=None,
                risk_level="LOW",
                confidence=0.0,
                recommended_decision="ALLOW",
                matched_events=[],
                details={"reason": "Empty sequence"}
            )

        patterns = self.registry.list_patterns()
        # Sort patterns deterministically by pattern_id to ensure strict evaluation order
        patterns.sort(key=lambda p: p.pattern_id)

        matching_assessments: List[BehaviorAssessment] = []

        for pattern in patterns:
            matched_events = self._match_pattern(sequence, pattern)
            if matched_events:
                assessment = BehaviorAssessment(
                    matched=True,
                    pattern_id=pattern.pattern_id,
                    pattern_name=pattern.name,
                    risk_level=pattern.risk_level,
                    confidence=pattern.confidence,
                    recommended_decision=pattern.recommended_decision,
                    matched_events=matched_events,
                    matched_sequence_ids=[sequence.sequence_id],
                    details={
                        "pattern_description": pattern.description,
                        "required_sequence": pattern.required_sequence,
                        "canonical_sequence": sequence.to_canonical_string(),
                        "max_gap_allowed": pattern.max_gap,
                        "allow_gaps": pattern.allow_gaps
                    }
                )
                matching_assessments.append(assessment)

        if not matching_assessments:
            return BehaviorAssessment(
                matched=False,
                pattern_id=None,
                pattern_name=None,
                risk_level="LOW",
                confidence=0.0,
                recommended_decision="ALLOW",
                matched_events=[],
                details={"canonical_sequence": sequence.to_canonical_string()}
            )

        # Risk priority ranking
        risk_priority = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        # Select highest risk assessment (and tiebreak by pattern_id deterministically)
        best_assessment = max(
            matching_assessments,
            key=lambda a: (risk_priority.get(a.risk_level, 0), a.confidence, a.pattern_id or "")
        )

        return best_assessment

    def _match_pattern(
        self, sequence: BehaviorSequence, pattern: BehaviorPattern
    ) -> Optional[List[BehaviorEvent]]:
        """
        Subsequence pattern matching algorithm with order enforcement and gap constraints.
        Returns list of matched BehaviorEvents if matched, else None.
        """
        # Scoping checks
        if pattern.scoped_tenant_id and pattern.scoped_tenant_id != sequence.tenant_id:
            return None
        if pattern.scoped_agent_id and pattern.scoped_agent_id != sequence.agent_id:
            return None

        req_seq = pattern.required_sequence
        if not req_seq:
            return None

        events = sequence.events
        if len(events) < pattern.min_sequence_length:
            return None

        # Helper recursive search for ordered subsequence
        return self._find_subsequence(events, req_seq, 0, 0, pattern.allow_gaps, pattern.max_gap)

    def _find_subsequence(
        self,
        events: List[BehaviorEvent],
        required: List[str],
        event_idx: int,
        req_idx: int,
        allow_gaps: bool,
        max_gap: int
    ) -> Optional[List[BehaviorEvent]]:
        """
        Recursively finds a matching ordered sequence of events.
        """
        if req_idx >= len(required):
            return []

        target_type = required[req_idx]

        for i in range(event_idx, len(events)):
            evt = events[i]
            if evt.event_type == target_type:
                # Check gap constraint from previous event index if req_idx > 0
                if req_idx > 0 and event_idx > 0:
                    gap = (i - event_idx)
                    if not allow_gaps and gap > 0:
                        continue
                    if allow_gaps and gap > max_gap:
                        continue

                # Recurse for next required item
                rest = self._find_subsequence(
                    events=events,
                    required=required,
                    event_idx=i + 1,
                    req_idx=req_idx + 1,
                    allow_gaps=allow_gaps,
                    max_gap=max_gap
                )

                if rest is not None:
                    return [evt] + rest

        return None
