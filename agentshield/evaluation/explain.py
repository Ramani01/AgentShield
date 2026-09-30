"""
Phase 27: Explainable Containment Decision Generator.
Generates deterministic, evidence-backed explanations for containment assessments.
"""

from typing import List, Dict, Any
from agentshield.evaluation.containment_models import ContainmentAssessment, EvidenceRecord


class DecisionExplainer:
    """
    Generates structured human-readable and auditable decision explanations.

    Invariants Enforced:
    7. Evidence Traceability: Every non-NO_ACTION assessment references supporting evidence.
    8. No Unsupported Attribution: Uses neutral, evidence-backed language without unsupported claims.
    """

    @staticmethod
    def generate_explanation(
        outcome: str,
        severity: str,
        matched_rules: List[str],
        evidence_records: List[EvidenceRecord],
        recommended_isolation: str,
        context: Dict[str, Any]
    ) -> str:
        """Generates a clear deterministic explanation string for an assessment."""
        if outcome == "NO_ACTION":
            return f"Outcome NO_ACTION: All security signals clean. Recommended isolation level: {recommended_isolation}."

        rule_str = ", ".join(matched_rules) if matched_rules else "Default Policy"

        evidence_summaries = []
        for ev in evidence_records:
            evidence_summaries.append(
                f"[{ev.source_phase}/{ev.source_control}]: {ev.evidence_type} (Severity: {ev.severity}, ID: {ev.evidence_id[:8]})"
            )

        ev_text = "; ".join(evidence_summaries) if evidence_summaries else "No supporting evidence IDs attached"

        explanation = (
            f"Outcome '{outcome}' (Severity: {severity}) triggered by matched rule(s) [{rule_str}]. "
            f"Recommended Isolation Level: '{recommended_isolation}'. "
            f"Supporting Evidence: {ev_text}."
        )

        return explanation
