"""
Unit and Integration Tests for Phase 29 Containment Benchmark & Security Evaluation Framework.
"""

import pytest
import time
from agentshield import AgentShield
from agentshield.benchmark import (
    BenchmarkScenario,
    BenchmarkRun,
    BenchmarkResult,
    BenchmarkMetrics,
    BenchmarkReport,
    BenchmarkScenarioRegistry,
    BenchmarkRunner,
    MetricsCalculator,
    BenchmarkEvaluator,
    BenchmarkReporter
)
from agentshield.containment import ContainmentState


# =====================================================================
# 1. SCENARIO REGISTRATION & REJECTION TESTS
# =====================================================================

def test_benchmark_scenario_registration():
    registry = BenchmarkScenarioRegistry()
    scenarios = registry.list_scenarios()
    assert len(scenarios) == 7
    ids = [s.scenario_id for s in scenarios]
    assert "SCENARIO-CAPABILITY-ESCALATION" in ids
    assert "SCENARIO-CONTAINMENT-ESCALATION" in ids


def test_unknown_benchmark_scenario_rejection():
    registry = BenchmarkScenarioRegistry()
    with pytest.raises(KeyError, match="Unknown benchmark scenario ID"):
        registry.get_scenario("SCENARIO-NONEXISTENT")


# =====================================================================
# 2. RUNNER EXECUTION TESTS
# =====================================================================

def test_single_scenario_benchmark():
    runner = BenchmarkRunner()
    results = runner.run_scenario("SCENARIO-BEHAVIORAL-RISK", iterations=5, warmup_iterations=1, tenant_id="t1", agent_id="a1")
    assert len(results) == 5
    for r in results:
        assert r.scenario_id == "SCENARIO-BEHAVIORAL-RISK"
        assert r.pass_status is True
        assert r.observed_outcome == "ESCALATE"


def test_multi_scenario_benchmark():
    runner = BenchmarkRunner()
    results = runner.run_benchmark(scenario_ids=["SCENARIO-CAPABILITY-ESCALATION", "SCENARIO-RUNTIME-DRIFT"], iterations=3, tenant_id="t1", agent_id="a1")
    assert len(results) == 6  # 2 scenarios * 3 iterations
    scenario_counts = {}
    for r in results:
        scenario_counts[r.scenario_id] = scenario_counts.get(r.scenario_id, 0) + 1
    assert scenario_counts["SCENARIO-CAPABILITY-ESCALATION"] == 3
    assert scenario_counts["SCENARIO-RUNTIME-DRIFT"] == 3


def test_configurable_iteration_count():
    runner = BenchmarkRunner()
    results = runner.run_benchmark(iterations=10, tenant_id="t1", agent_id="a1")
    # 7 default scenarios * 10 iterations = 70 results
    assert len(results) == 70


def test_deterministic_benchmark_execution():
    runner = BenchmarkRunner()
    res1 = runner.run_scenario("SCENARIO-CONTAINMENT-ESCALATION", iterations=2, tenant_id="dt", agent_id="da")
    res2 = runner.run_scenario("SCENARIO-CONTAINMENT-ESCALATION", iterations=2, tenant_id="dt", agent_id="da")

    for r1, r2 in zip(res1, res2):
        assert r1.scenario_id == r2.scenario_id
        assert r1.observed_outcome == r2.observed_outcome
        assert r1.matched_rules == r2.matched_rules
        assert r1.pass_status == r2.pass_status == True


# =====================================================================
# 3. EXPECTED VS OBSERVED MATCHING TESTS
# =====================================================================

def test_expected_observed_matching():
    res = BenchmarkResult(
        scenario_id="SCENARIO-GRAPH-RISK",
        expected_outcome="REVIEW",
        observed_outcome="REVIEW",
        expected_isolation="RESTRICTED",
        observed_isolation="RESTRICTED",
        pass_status=True
    )
    assert res.pass_status is True


def test_expected_observed_mismatch_detection():
    res = BenchmarkResult(
        scenario_id="SCENARIO-MISMATCH",
        expected_outcome="ESCALATE",
        observed_outcome="NO_ACTION",
        expected_isolation="FULL",
        observed_isolation="NONE",
        pass_status=False
    )
    metrics = MetricsCalculator.calculate_metrics([res])
    assert metrics.failed_count == 1
    assert metrics.pass_rate == 0.0


# =====================================================================
# 4. SECURITY INVARIANT TESTS
# =====================================================================

def test_tenant_isolation_in_benchmark():
    evaluator = BenchmarkEvaluator()
    results = [BenchmarkResult(scenario_id="S1", observed_outcome="REVIEW", evidence_ids=["ev1"], metadata={"simulation_only": True})]
    invariants = evaluator.verify_security_invariants(results, tenant_id="t_alpha", agent_id="a_alpha")
    assert invariants["tenant_isolation"] is True


def test_agent_isolation_in_benchmark():
    evaluator = BenchmarkEvaluator()
    results = [BenchmarkResult(scenario_id="S1", observed_outcome="REVIEW", evidence_ids=["ev1"], metadata={"simulation_only": True})]
    invariants = evaluator.verify_security_invariants(results, tenant_id="t1", agent_id="a1")
    assert invariants["agent_isolation"] is True


def test_capability_invariance():
    evaluator = BenchmarkEvaluator()
    invariants = evaluator.verify_security_invariants([])
    assert invariants["no_capability_elevation"] is True


def test_policy_invariance():
    evaluator = BenchmarkEvaluator()
    invariants = evaluator.verify_security_invariants([])
    assert invariants["no_policy_override"] is True


def test_containment_state_invariance():
    shield = AgentShield()
    shield.containment_manager.request_emergency_containment("t_inv", "a_inv")
    evaluator = BenchmarkEvaluator(shield=shield)
    invariants = evaluator.verify_security_invariants([], tenant_id="t_inv", agent_id="a_inv")
    assert invariants["no_automatic_release"] is True


def test_release_invariance():
    shield = AgentShield()
    shield.containment_manager.request_emergency_containment("t_rel", "a_rel")
    runner = BenchmarkRunner(shield=shield)
    results = runner.run_scenario("SCENARIO-RECOVERY-REVIEW", iterations=1, tenant_id="t_rel", agent_id="a_rel")
    assert results[0].observed_outcome == "RELEASE_REVIEW"

    # Verify state in ContainmentManager remains CONTAINED
    status = shield.containment_manager.get_containment_status("t_rel", "a_rel")
    assert status["current_state"] == ContainmentState.CONTAINED


def test_evidence_traceability_in_benchmark():
    res_valid = BenchmarkResult(scenario_id="S1", observed_outcome="ESCALATE", evidence_ids=["ev_101"])
    res_invalid = BenchmarkResult(scenario_id="S2", observed_outcome="ESCALATE", evidence_ids=[])

    evaluator = BenchmarkEvaluator()
    assert evaluator.verify_security_invariants([res_valid])["evidence_traceability"] is True
    assert evaluator.verify_security_invariants([res_invalid])["evidence_traceability"] is False


# =====================================================================
# 5. METRICS & LATENCY CALCULATIONS
# =====================================================================

def test_latency_measurement():
    runner = BenchmarkRunner()
    results = runner.run_scenario("SCENARIO-RUNTIME-DRIFT", iterations=3)
    for r in results:
        assert r.latency_ms > 0.0


def test_median_calculation():
    r1 = BenchmarkResult(scenario_id="S1", latency_ms=10.0, pass_status=True)
    r2 = BenchmarkResult(scenario_id="S1", latency_ms=20.0, pass_status=True)
    r3 = BenchmarkResult(scenario_id="S1", latency_ms=30.0, pass_status=True)

    metrics = MetricsCalculator.calculate_metrics([r1, r2, r3])
    assert metrics.median_latency_ms == 20.0
    assert metrics.min_latency_ms == 10.0
    assert metrics.max_latency_ms == 30.0
    assert metrics.avg_latency_ms == 20.0


def test_p95_calculation():
    lats = [float(i) for i in range(1, 101)]  # 1..100
    results = [BenchmarkResult(scenario_id="S1", latency_ms=l, pass_status=True) for l in lats]
    metrics = MetricsCalculator.calculate_metrics(results)
    assert 94.0 <= metrics.p95_latency_ms <= 96.0


def test_p99_calculation():
    lats = [float(i) for i in range(1, 101)]
    results = [BenchmarkResult(scenario_id="S1", latency_ms=l, pass_status=True) for l in lats]
    metrics = MetricsCalculator.calculate_metrics(results)
    assert 98.0 <= metrics.p99_latency_ms <= 100.0


def test_throughput_calculation():
    results = [BenchmarkResult(scenario_id="S1", latency_ms=5.0, pass_status=True) for _ in range(10)]
    metrics = MetricsCalculator.calculate_metrics(results, total_time_seconds=2.0)
    assert metrics.throughput_eps == 5.0  # 10 / 2.0 = 5.0 eps


def test_scenario_level_metrics():
    r1 = BenchmarkResult(scenario_id="S_A", latency_ms=10.0, pass_status=True)
    r2 = BenchmarkResult(scenario_id="S_A", latency_ms=20.0, pass_status=False)
    r3 = BenchmarkResult(scenario_id="S_B", latency_ms=5.0, pass_status=True)

    metrics = MetricsCalculator.calculate_metrics([r1, r2, r3])
    assert "S_A" in metrics.scenario_metrics
    assert "S_B" in metrics.scenario_metrics

    sm_a = metrics.scenario_metrics["S_A"]
    assert sm_a["iterations"] == 2
    assert sm_a["passed_count"] == 1
    assert sm_a["failed_count"] == 1
    assert sm_a["pass_rate"] == 0.5


def test_overall_metrics():
    r1 = BenchmarkResult(scenario_id="S1", latency_ms=10.0, pass_status=True)
    r2 = BenchmarkResult(scenario_id="S1", latency_ms=20.0, pass_status=True)
    metrics = MetricsCalculator.calculate_metrics([r1, r2])
    assert metrics.total_evaluations == 2
    assert metrics.passed_count == 2
    assert metrics.failed_count == 0
    assert metrics.pass_rate == 1.0


# =====================================================================
# 6. REPORTING & EDGE CASES
# =====================================================================

def test_report_generation_and_markdown_formatting():
    runner = BenchmarkRunner()
    results = runner.run_benchmark(scenario_ids=["SCENARIO-RUNTIME-DRIFT"], iterations=2, tenant_id="rpt_t", agent_id="rpt_a")
    report = BenchmarkReporter.generate_report("rpt_t", "rpt_a", results)

    assert report.tenant_id == "rpt_t"
    assert report.agent_id == "rpt_a"
    assert report.metrics.total_evaluations == 2
    assert report.summary["overall_status"] == "PASS"

    md_text = BenchmarkReporter.format_markdown_report(report)
    assert "# [AgentShield] Containment Benchmark Report" in md_text
    assert "`SCENARIO-RUNTIME-DRIFT`" in md_text
    assert "**Tenant ID:** `rpt_t`" in md_text


def test_empty_benchmark_handling():
    runner = BenchmarkRunner()
    results = runner.run_benchmark(scenario_ids=[], iterations=5)
    assert len(results) == 0

    metrics = MetricsCalculator.calculate_metrics(results)
    assert metrics.total_evaluations == 0
    assert metrics.pass_rate == 0.0

    report = BenchmarkReporter.generate_report("t", "a", results)
    assert report.metrics.total_evaluations == 0


def test_invalid_benchmark_configuration_handling():
    runner = BenchmarkRunner()
    with pytest.raises(ValueError, match="Iterations must be non-negative"):
        runner.run_benchmark(iterations=-1)

    with pytest.raises(ValueError, match="Warmup iterations must be non-negative"):
        runner.run_benchmark(warmup_iterations=-5)
