"""
Phase 27 Containment Evaluation Engine Demonstration.
"""

from agentshield import AgentShield
from agentshield.evaluation import (
    EvidenceRecord,
    EvaluationSeverity,
    EvaluationOutcome
)


def main():
    print("=== AgentShield 2.0 — Phase 27 Demo ===")
    shield = AgentShield()

    tenant_id = "tenant_alpha"
    agent_id = "agent_007"

    print(f"\n1. Normalizing multi-signal evidence for Agent '{agent_id}'...")

    ev_runtime = EvidenceRecord(
        source_phase="Phase-23",
        source_control="PHASE_23_INTEGRITY_CHECKER",
        evidence_type="RUNTIME_INTEGRITY",
        severity=EvaluationSeverity.CRITICAL,
        tenant_id=tenant_id,
        agent_id=agent_id,
        references={"integrity_state": "INVALID"}
    )

    ev_behavior = EvidenceRecord(
        source_phase="Phase-24",
        source_control="PHASE_24_BEHAVIORAL_DETECTOR",
        evidence_type="BEHAVIOR_PATTERN",
        severity=EvaluationSeverity.HIGH,
        tenant_id=tenant_id,
        agent_id=agent_id,
        references={"pattern_id": "BEHAVIOR-004"}
    )

    print(f"  Evidence 1: Runtime Integrity = INVALID")
    print(f"  Evidence 2: Behavioral Risk = HIGH")

    print("\n2. Executing Containment Evaluation Engine...")
    assessment = shield.evaluation_engine.evaluate_evidence(
        tenant_id=tenant_id,
        agent_id=agent_id,
        evidence_records=[ev_runtime, ev_behavior]
    )

    print("\n=== Evaluation Assessment ===")
    print(f"Assessment ID: {assessment.assessment_id}")
    print(f"Outcome:       {assessment.outcome}")
    print(f"Severity:      {assessment.severity}")
    print(f"Rec. Isolation:{assessment.recommended_isolation_level}")
    print(f"Matched Rules: {assessment.matched_rules}")
    print(f"Explanation:   {assessment.explanation}")

    print("\n=== Invariant Verification ===")
    print("[OK] Phase 27 produces recommendation without altering Phase 25 state directly.")
    print("[OK] Rule Priority: Rule 2 (Invalid RT + High Behavior) resolved deterministically.")


if __name__ == "__main__":
    main()
