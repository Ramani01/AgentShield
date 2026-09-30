"""
Phase 28: Simulation Report Generator.
Generates structured, auditable reports summarizing safe adversarial simulation runs.
"""

import time
from typing import List, Dict, Any, Optional
from agentshield.simulation.models import (
    SimulationResult,
    SimulationReport,
    SimulationOutcomeStatus
)


class SimulationReportGenerator:
    """
    Aggregates SimulationResult records into auditable SimulationReport documents.

    Safety:
    - Never includes credentials, tokens, or raw sensitive payloads.
    - Preserves tenant and agent boundaries.
    """

    @staticmethod
    def generate_report(
        tenant_id: str,
        agent_id: str,
        results: List[SimulationResult]
    ) -> SimulationReport:
        """Generates an audit-ready SimulationReport from simulation results."""
        pass_count = sum(1 for r in results if r.status == SimulationOutcomeStatus.PASS)
        fail_count = sum(1 for r in results if r.status == SimulationOutcomeStatus.FAIL)
        inconclusive_count = sum(1 for r in results if r.status == SimulationOutcomeStatus.INCONCLUSIVE)

        total = len(results)
        success_rate = (pass_count / total) if total > 0 else 0.0

        summary = {
            "total_scenarios_evaluated": total,
            "passed": pass_count,
            "failed": fail_count,
            "inconclusive": inconclusive_count,
            "success_rate_pct": round(success_rate * 100.0, 2),
            "all_passed": (fail_count == 0 and total > 0)
        }

        return SimulationReport(
            tenant_id=tenant_id,
            agent_id=agent_id,
            generated_at=time.time(),
            scenario_count=total,
            pass_count=pass_count,
            fail_count=fail_count,
            inconclusive_count=inconclusive_count,
            results=results,
            summary=summary
        )
