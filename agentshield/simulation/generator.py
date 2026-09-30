"""
Phase 28: Deterministic Event Generator for Adversarial Simulation.
Generates synthetic, safe SimulationEvent instances for scenario execution.
"""

import time
from typing import List, Optional, Dict, Any
from agentshield.simulation.models import SimulationEvent, SimulationScenario
from agentshield.simulation.scenarios import ScenarioRegistry


class SimulationGenerator:
    """
    Generates synthetic, safe SimulationEvent streams deterministically scoped to (tenant_id, agent_id).

    Safety Rules:
    - Sets simulation_only = True on every event.
    - Deterministic output ordering.
    - Does not execute code or shell commands.
    """

    def __init__(self, registry: Optional[ScenarioRegistry] = None):
        self.registry = registry or ScenarioRegistry(include_defaults=True)

    def generate_events_for_scenario(
        self,
        scenario_id: str,
        tenant_id: str = "default",
        agent_id: str = "default",
        fixed_timestamp: Optional[float] = None
    ) -> List[SimulationEvent]:
        """
        Retrieves registered scenario and generates concrete synthetic events.
        """
        scenario = self.registry.get_scenario(scenario_id)
        events: List[SimulationEvent] = []
        base_time = fixed_timestamp if fixed_timestamp is not None else 1700000000.0

        for idx, tpl in enumerate(scenario.events_template):
            event_type = tpl.get("event_type", "SYNTHETIC_SIGNAL")
            event_id = f"sim_{scenario.scenario_id.lower().replace('-', '_')}_ev_{idx+1}"

            ev = SimulationEvent(
                event_id=event_id,
                event_type=event_type,
                source_phase=scenario.target_phase,
                tenant_id=tenant_id,
                agent_id=agent_id,
                timestamp=base_time + (idx * 1.0),
                simulation_only=True,
                payload=dict(tpl),
                expected_signal=scenario.expected_signal,
                metadata={
                    "scenario_id": scenario.scenario_id,
                    "scenario_name": scenario.name,
                    "scenario_type": scenario.scenario_type,
                    "target_phase": scenario.target_phase,
                    "step_index": idx + 1
                }
            )
            events.append(ev)

        return events
