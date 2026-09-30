"""
Phase 29: Benchmark Runner.
Executes deterministic, non-destructive containment benchmarks over AgentShield security controls.
"""

import time
import logging
from typing import Optional, List, Dict, Any
from typing import Optional, List, Dict, Any
from agentshield.benchmark.models import BenchmarkResult, BenchmarkScenario
from agentshield.benchmark.scenarios import BenchmarkScenarioRegistry
from agentshield.simulation.executor import SimulationExecutor

logger = logging.getLogger("AgentShield.BenchmarkRunner")


class BenchmarkRunner:
    """
    Executes benchmark evaluations over Phase 28 synthetic scenarios.

    Safety & Operational Guarantees:
    - Zero shell execution, subprocesses, network requests, or OS-level infrastructure changes.
    - Zero capability grant modifications or real containment releases.
    - Observes and measures existing security engine outputs only.
    - Scoped strictly to explicit (tenant_id, agent_id).
    """

    def __init__(
        self,
        shield: Optional[Any] = None,
        registry: Optional[BenchmarkScenarioRegistry] = None,
        executor: Optional[SimulationExecutor] = None
    ):
        if shield is None:
            from agentshield import AgentShield
            shield = AgentShield()
        self.shield = shield
        self.registry = registry or BenchmarkScenarioRegistry()
        self.executor = executor or SimulationExecutor(shield=self.shield)

    def run_scenario(
        self,
        scenario_id: str,
        iterations: int = 1,
        warmup_iterations: int = 0,
        tenant_id: str = "default",
        agent_id: str = "default"
    ) -> List[BenchmarkResult]:
        """Runs a single scenario for N iterations with optional warmup runs."""
        scenario = self.registry.get_scenario(scenario_id)
        return self._execute_benchmark([scenario], iterations, warmup_iterations, tenant_id, agent_id)

    def run_benchmark(
        self,
        scenario_ids: Optional[List[str]] = None,
        iterations: int = 1,
        warmup_iterations: int = 0,
        tenant_id: str = "default",
        agent_id: str = "default"
    ) -> List[BenchmarkResult]:
        """Runs multiple scenarios for N iterations with optional warmup runs."""
        if scenario_ids is None:
            scenarios = self.registry.list_scenarios()
        else:
            scenarios = [self.registry.get_scenario(sid) for sid in scenario_ids]

        return self._execute_benchmark(scenarios, iterations, warmup_iterations, tenant_id, agent_id)

    def _execute_benchmark(
        self,
        scenarios: List[BenchmarkScenario],
        iterations: int,
        warmup_iterations: int,
        tenant_id: str,
        agent_id: str
    ) -> List[BenchmarkResult]:
        """Internal execution loop measuring latency and evaluating correctness."""
        if iterations < 0:
            raise ValueError("Iterations must be non-negative (>= 0)")
        if warmup_iterations < 0:
            raise ValueError("Warmup iterations must be non-negative (>= 0)")
        if not scenarios:
            return []

        # 1. Warmup runs (discarded from metrics)
        for _ in range(warmup_iterations):
            for s in scenarios:
                self.executor.execute_scenario(s.scenario_id, tenant_id=tenant_id, agent_id=agent_id)

        # 2. Measured benchmark runs
        results: List[BenchmarkResult] = []
        for it in range(1, iterations + 1):
            for s in scenarios:
                t0 = time.perf_counter()
                sim_res = self.executor.execute_scenario(s.scenario_id, tenant_id=tenant_id, agent_id=agent_id)
                t1 = time.perf_counter()

                latency_ms = (t1 - t0) * 1000.0

                pass_status = (
                    sim_res.actual_outcome == s.expected_outcome and
                    sim_res.actual_isolation_level == s.expected_isolation
                )

                bm_res = BenchmarkResult(
                    scenario_id=s.scenario_id,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    iteration=it,
                    expected_outcome=s.expected_outcome,
                    observed_outcome=sim_res.actual_outcome,
                    expected_isolation=s.expected_isolation,
                    observed_isolation=sim_res.actual_isolation_level,
                    matched_rules=sim_res.matched_rules,
                    evidence_ids=sim_res.evidence_ids,
                    latency_ms=latency_ms,
                    pass_status=pass_status,
                    metadata={
                        "target_phase": s.target_phase,
                        "actual_signal": sim_res.actual_signal,
                        "simulation_only": True
                    }
                )
                results.append(bm_res)

        return results
