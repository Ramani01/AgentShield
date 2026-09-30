"""
Phase 29: Containment Benchmark & Security Evaluation Models.
Defines typed models for scenarios, runs, results, metrics, and audit reports.
"""

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional


@dataclass
class BenchmarkScenario:
    """Represents a benchmark scenario specification."""
    scenario_id: str
    name: str
    description: str
    target_phase: str
    expected_outcome: str
    expected_isolation: str = "NONE"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkRun:
    """Configuration for a single benchmark execution run."""
    run_id: str = field(default_factory=lambda: f"bm_run_{uuid.uuid4().hex[:12]}")
    scenario_id: str = ""
    tenant_id: str = "default"
    agent_id: str = "default"
    iteration: int = 1
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkResult:
    """Observed result from a single benchmark scenario iteration."""
    benchmark_id: str = field(default_factory=lambda: f"bm_res_{uuid.uuid4().hex[:12]}")
    scenario_id: str = ""
    tenant_id: str = "default"
    agent_id: str = "default"
    iteration: int = 1
    expected_outcome: str = ""
    observed_outcome: str = ""
    expected_isolation: str = "NONE"
    observed_isolation: str = "NONE"
    matched_rules: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    latency_ms: float = 0.0
    pass_status: bool = False
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.benchmark_id:
            self.benchmark_id = f"bm_res_{uuid.uuid4().hex[:12]}"
        if not self.timestamp:
            self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkMetrics:
    """Aggregated correctness, latency, and throughput metrics."""
    total_evaluations: int = 0
    passed_count: int = 0
    failed_count: int = 0
    pass_rate: float = 0.0
    mismatch_count: int = 0
    min_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0
    median_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    throughput_eps: float = 0.0
    total_time_seconds: float = 0.0
    scenario_metrics: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkReport:
    """Full auditable benchmark report containing metrics, invariant results, and summary."""
    report_id: str = field(default_factory=lambda: f"bm_rpt_{uuid.uuid4().hex[:12]}")
    tenant_id: str = "default"
    agent_id: str = "default"
    generated_at: float = field(default_factory=time.time)
    metrics: Optional[BenchmarkMetrics] = None
    scenario_metrics: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    invariant_results: Dict[str, bool] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.report_id:
            self.report_id = f"bm_rpt_{uuid.uuid4().hex[:12]}"
        if not self.generated_at:
            self.generated_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        if self.metrics:
            res["metrics"] = self.metrics.to_dict()
        return res
