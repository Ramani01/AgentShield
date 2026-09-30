"""
Phase 28: Safe Adversarial Simulation Evaluator.
Validates simulation outcomes against expected security signals and containment decisions.
"""

from typing import List, Dict, Any, Optional
from agentshield.simulation.models import (
    SimulationResult,
    SimulationOutcomeStatus,
    SimulationScenario
)


class SimulationEvaluator:
    """
    Evaluates simulation execution results against authoritative security expectations.

    Invariants Enforced:
    - Never silently classifies unexpected result as PASS.
    - Captures exact evidence IDs and matched rule IDs.
    - Scopes validation to tenant_id and agent_id context.
    """

    @staticmethod
    def evaluate_result(result: SimulationResult) -> Dict[str, Any]:
        """
        Performs strict comparison of expected vs actual findings.
        """
        signal_match = (result.expected_signal == result.actual_signal)
        outcome_match = (result.expected_outcome == result.actual_outcome)
        isolation_match = (result.expected_isolation_level == result.actual_isolation_level)

        is_passed = signal_match and outcome_match

        mismatches = []
        if not signal_match:
            mismatches.append(f"Signal mismatch: expected '{result.expected_signal}', got '{result.actual_signal}'")
        if not outcome_match:
            mismatches.append(f"Outcome mismatch: expected '{result.expected_outcome}', got '{result.actual_outcome}'")
        if not isolation_match:
            mismatches.append(f"Isolation level mismatch: expected '{result.expected_isolation_level}', got '{result.actual_isolation_level}'")

        status = SimulationOutcomeStatus.PASS if is_passed else SimulationOutcomeStatus.FAIL

        return {
            "simulation_id": result.simulation_id,
            "scenario_id": result.scenario_id,
            "tenant_id": result.tenant_id,
            "agent_id": result.agent_id,
            "status": status,
            "is_passed": is_passed,
            "mismatches": mismatches,
            "matched_rules": result.matched_rules,
            "evidence_ids": result.evidence_ids,
            "explanation": result.explanation
        }

    @staticmethod
    def evaluate_batch(results: List[SimulationResult]) -> Dict[str, Any]:
        """Evaluates a list of simulation results and aggregates statistics."""
        pass_count = sum(1 for r in results if r.status == SimulationOutcomeStatus.PASS)
        fail_count = sum(1 for r in results if r.status == SimulationOutcomeStatus.FAIL)
        inconclusive_count = sum(1 for r in results if r.status == SimulationOutcomeStatus.INCONCLUSIVE)

        return {
            "total": len(results),
            "pass_count": pass_count,
            "fail_count": fail_count,
            "inconclusive_count": inconclusive_count,
            "success_rate": (pass_count / len(results)) if results else 0.0
        }
