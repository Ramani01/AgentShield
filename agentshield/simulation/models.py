"""
Phase 28: Safe Adversarial Agent Simulation Models.
Defines typed models for scenarios, synthetic events, steps, simulation results, and audit reports.
"""

import time
import uuid
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional


class SimulationOutcomeStatus(str, Enum):
    """Result status of a safe adversarial scenario evaluation."""
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class SimulationEvent:
    """
    Synthetic security event generated during safe adversarial simulation.
    Strictly marked with simulation_only = True.
    """
    event_id: str = field(default_factory=lambda: f"sim_ev_{uuid.uuid4().hex[:12]}")
    event_type: str = "SYNTHETIC_SIGNAL"
    source_phase: str = "Phase-28"
    tenant_id: str = "default"
    agent_id: str = "default"
    timestamp: float = field(default_factory=time.time)
    simulation_only: bool = True  # Safety invariant: Must always be True
    payload: Dict[str, Any] = field(default_factory=dict)
    expected_signal: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Enforce safety invariant
        self.simulation_only = True
        if not self.event_id:
            self.event_id = f"sim_ev_{uuid.uuid4().hex[:12]}"
        if not self.timestamp:
            self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SimulationStep:
    """Single step within a simulation scenario execution."""
    step_id: str = field(default_factory=lambda: f"step_{uuid.uuid4().hex[:8]}")
    step_number: int = 1
    description: str = ""
    event: Optional[SimulationEvent] = None
    expected_signal: Optional[str] = None
    observed_signal: Optional[str] = None
    matched: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        if self.event:
            res["event"] = self.event.to_dict()
        return res


@dataclass
class SimulationScenario:
    """
    Predefined, immutable adversarial simulation scenario definition.
    Contains no executable commands or dangerous scripts.
    """
    scenario_id: str
    name: str
    description: str
    scenario_type: str
    target_phase: str
    expected_signal: str
    expected_outcome: str
    expected_isolation_level: str = "NONE"
    events_template: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SimulationResult:
    """Detailed evaluation result comparing expected vs actual simulation findings."""
    simulation_id: str = field(default_factory=lambda: f"sim_res_{uuid.uuid4().hex[:12]}")
    scenario_id: str = ""
    scenario_name: str = ""
    tenant_id: str = "default"
    agent_id: str = "default"
    status: str = SimulationOutcomeStatus.INCONCLUSIVE
    expected_signal: str = ""
    actual_signal: str = ""
    expected_outcome: str = ""
    actual_outcome: str = ""
    expected_isolation_level: str = "NONE"
    actual_isolation_level: str = "NONE"
    matched_rules: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    explanation: str = ""
    step_results: List[SimulationStep] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.simulation_id:
            self.simulation_id = f"sim_res_{uuid.uuid4().hex[:12]}"
        if not self.created_at:
            self.created_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["step_results"] = [s.to_dict() for s in self.step_results]
        return res


@dataclass
class SimulationReport:
    """Audit-ready report summarizing one or more adversarial simulation runs."""
    report_id: str = field(default_factory=lambda: f"sim_rpt_{uuid.uuid4().hex[:12]}")
    tenant_id: str = "default"
    agent_id: str = "default"
    generated_at: float = field(default_factory=time.time)
    scenario_count: int = 0
    pass_count: int = 0
    fail_count: int = 0
    inconclusive_count: int = 0
    results: List[SimulationResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.report_id:
            self.report_id = f"sim_rpt_{uuid.uuid4().hex[:12]}"
        if not self.generated_at:
            self.generated_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["results"] = [r.to_dict() for r in self.results]
        return res
