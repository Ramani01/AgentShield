"""
Phase 29: Benchmark Scenario Registry.
Reuses safe synthetic scenarios from Phase 28 without duplication or real attack logic.
"""

from typing import List, Dict, Optional
from agentshield.simulation.scenarios import ScenarioRegistry as SimulationScenarioRegistry
from agentshield.benchmark.models import BenchmarkScenario


class BenchmarkScenarioRegistry:
    """
    Registry for Phase 29 containment benchmark scenarios.
    Reuses Phase 28 safe scenario definitions.
    """

    def __init__(self, simulation_registry: Optional[SimulationScenarioRegistry] = None):
        self.sim_registry = simulation_registry or SimulationScenarioRegistry(include_defaults=True)
        self._scenarios: Dict[str, BenchmarkScenario] = {}
        self._load_scenarios_from_simulation()

    def _load_scenarios_from_simulation(self) -> None:
        """Imports safe scenarios from Phase 28 ScenarioRegistry."""
        sim_scenarios = self.sim_registry.list_scenarios()
        for s in sim_scenarios:
            bm_s = BenchmarkScenario(
                scenario_id=s.scenario_id,
                name=s.name,
                description=s.description,
                target_phase=s.target_phase,
                expected_outcome=s.expected_outcome,
                expected_isolation=s.expected_isolation_level,
                metadata={"scenario_type": s.scenario_type}
            )
            self._scenarios[s.scenario_id] = bm_s

    def get_scenario(self, scenario_id: str) -> BenchmarkScenario:
        """Retrieves benchmark scenario by ID."""
        if scenario_id not in self._scenarios:
            raise KeyError(f"Unknown benchmark scenario ID: {scenario_id}")
        return self._scenarios[scenario_id]

    def list_scenarios(self) -> List[BenchmarkScenario]:
        """Returns all benchmark scenarios sorted deterministically by scenario_id."""
        scenarios = list(self._scenarios.values())
        scenarios.sort(key=lambda s: s.scenario_id)
        return scenarios
