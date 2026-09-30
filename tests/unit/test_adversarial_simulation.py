"""
Unit and Integration Tests for Phase 28 Safe Adversarial Agent Simulation.
"""

import pytest
import time
from agentshield import AgentShield
from agentshield.simulation import (
    SimulationScenario,
    SimulationEvent,
    SimulationResult,
    SimulationReport,
    SimulationOutcomeStatus,
    ScenarioRegistry,
    SimulationGenerator,
    SimulationExecutor,
    SimulationEvaluator,
    SimulationReportGenerator
)
from agentshield.containment import ContainmentState


# =====================================================================
# 1. SCENARIO REGISTRY TESTS
# =====================================================================

def test_scenario_registration_and_list():
    registry = ScenarioRegistry(include_defaults=True)
    scenarios = registry.list_scenarios()
    assert len(scenarios) == 7

    ids = [s.scenario_id for s in scenarios]
    assert "SCENARIO-CAPABILITY-ESCALATION" in ids
    assert "SCENARIO-POLICY-DENIAL" in ids
    assert "SCENARIO-BEHAVIORAL-RISK" in ids
    assert "SCENARIO-RUNTIME-DRIFT" in ids
    assert "SCENARIO-GRAPH-RISK" in ids
    assert "SCENARIO-CONTAINMENT-ESCALATION" in ids
    assert "SCENARIO-RECOVERY-REVIEW" in ids


def test_duplicate_scenario_rejection():
    registry = ScenarioRegistry(include_defaults=True)
    dup = SimulationScenario(
        scenario_id="SCENARIO-CAPABILITY-ESCALATION",
        name="Duplicate",
        description="Dup",
        scenario_type="CAPABILITY_ESCALATION",
        target_phase="Phase-21",
        expected_signal="CAPABILITY_DENIED",
        expected_outcome="REVIEW"
    )
    with pytest.raises(ValueError, match="Duplicate scenario registration rejected"):
        registry.register_scenario(dup)


def test_unknown_scenario_rejection():
    registry = ScenarioRegistry(include_defaults=True)
    with pytest.raises(KeyError, match="Unknown scenario ID"):
        registry.get_scenario("SCENARIO-UNKNOWN-NONEXISTENT")


# =====================================================================
# 2. GENERATOR & DETERMINISM TESTS
# =====================================================================

def test_deterministic_scenario_generation():
    generator = SimulationGenerator()
    events1 = generator.generate_events_for_scenario("SCENARIO-BEHAVIORAL-RISK", tenant_id="t1", agent_id="a1", fixed_timestamp=1000.0)
    events2 = generator.generate_events_for_scenario("SCENARIO-BEHAVIORAL-RISK", tenant_id="t1", agent_id="a1", fixed_timestamp=1000.0)

    assert len(events1) == len(events2)
    assert events1[0].event_id == events2[0].event_id
    assert events1[0].timestamp == events2[0].timestamp
    assert events1[0].tenant_id == events2[0].tenant_id == "t1"
    assert events1[0].agent_id == events2[0].agent_id == "a1"


def test_simulation_only_marker_presence():
    generator = SimulationGenerator()
    events = generator.generate_events_for_scenario("SCENARIO-CONTAINMENT-ESCALATION", tenant_id="t1", agent_id="a1")
    for ev in events:
        assert ev.simulation_only is True


# =====================================================================
# 3. SCENARIO EXECUTION TESTS (SCENARIOS 1-7)
# =====================================================================

def test_scenario_capability_escalation_simulation():
    executor = SimulationExecutor()
    res = executor.execute_scenario("SCENARIO-CAPABILITY-ESCALATION", tenant_id="t1", agent_id="a1")
    assert res.status == SimulationOutcomeStatus.PASS
    assert res.actual_signal == "CAPABILITY_DENIED"
    assert res.actual_outcome == "REVIEW"
    assert res.actual_isolation_level == "RESTRICTED"


def test_scenario_policy_denial_simulation():
    executor = SimulationExecutor()
    res = executor.execute_scenario("SCENARIO-POLICY-DENIAL", tenant_id="t1", agent_id="a1")
    assert res.status == SimulationOutcomeStatus.PASS
    assert res.actual_signal == "COMMUNICATION_DENY"
    assert res.actual_outcome == "REVIEW"


def test_scenario_behavioral_risk_simulation():
    executor = SimulationExecutor()
    res = executor.execute_scenario("SCENARIO-BEHAVIORAL-RISK", tenant_id="t1", agent_id="a1")
    assert res.status == SimulationOutcomeStatus.PASS
    assert res.actual_signal == "BEHAVIOR_PATTERN_MATCH"
    assert res.actual_outcome == "ESCALATE"
    assert res.actual_isolation_level == "FULL"


def test_scenario_runtime_drift_simulation():
    executor = SimulationExecutor()
    res = executor.execute_scenario("SCENARIO-RUNTIME-DRIFT", tenant_id="t1", agent_id="a1")
    assert res.status == SimulationOutcomeStatus.PASS
    assert res.actual_signal == "RUNTIME_INTEGRITY_INVALID"
    assert res.actual_outcome == "ESCALATE"
    assert res.actual_isolation_level == "FULL"


def test_scenario_graph_risk_simulation():
    executor = SimulationExecutor()
    res = executor.execute_scenario("SCENARIO-GRAPH-RISK", tenant_id="t1", agent_id="a1")
    assert res.status == SimulationOutcomeStatus.PASS
    assert res.actual_signal == "SECURITY_GRAPH_PATH_SUSPICIOUS"
    assert res.actual_outcome == "REVIEW"


def test_scenario_containment_escalation_simulation():
    executor = SimulationExecutor()
    res = executor.execute_scenario("SCENARIO-CONTAINMENT-ESCALATION", tenant_id="t1", agent_id="a1")
    assert res.status == SimulationOutcomeStatus.PASS
    assert res.actual_signal == "CONTAINMENT_ESCALATE_RECOMMENDED"
    assert res.actual_outcome == "ESCALATE"
    assert res.actual_isolation_level == "FULL"


def test_scenario_recovery_review_simulation():
    executor = SimulationExecutor()
    res = executor.execute_scenario("SCENARIO-RECOVERY-REVIEW", tenant_id="t1", agent_id="a1")
    assert res.status == SimulationOutcomeStatus.PASS
    assert res.actual_signal == "CONTAINMENT_RELEASE_REVIEW_RECOMMENDED"
    assert res.actual_outcome == "RELEASE_REVIEW"
    assert res.actual_isolation_level == "NONE"


# =====================================================================
# 4. ISOLATION & NO-SIDE-EFFECT TESTS
# =====================================================================

def test_tenant_and_agent_isolation():
    executor = SimulationExecutor()
    res_t1 = executor.execute_scenario("SCENARIO-BEHAVIORAL-RISK", tenant_id="tenant_A", agent_id="agent_1")
    res_t2 = executor.execute_scenario("SCENARIO-BEHAVIORAL-RISK", tenant_id="tenant_B", agent_id="agent_2")

    assert res_t1.tenant_id == "tenant_A"
    assert res_t1.agent_id == "agent_1"
    assert res_t2.tenant_id == "tenant_B"
    assert res_t2.agent_id == "agent_2"


def test_no_real_side_effects_containment_unchanged():
    shield = AgentShield()
    shield.containment_manager.request_emergency_containment("t1", "a1")

    # Run simulation
    res = shield.simulation_executor.execute_scenario("SCENARIO-RECOVERY-REVIEW", tenant_id="t1", agent_id="a1")
    assert res.actual_outcome == "RELEASE_REVIEW"

    # Verify real containment manager state remains CONTAINED (no real automatic release)
    status = shield.containment_manager.get_containment_status("t1", "a1")
    assert status["current_state"] == ContainmentState.CONTAINED


# =====================================================================
# 5. EXPECTED VS ACTUAL EVALUATOR & MISMATCH TESTS
# =====================================================================

def test_expected_actual_mismatch_detection():
    # Construct a result with intentional signal mismatch
    res = SimulationResult(
        scenario_id="SCENARIO-TEST",
        expected_signal="EXPECTED_SIGNAL",
        actual_signal="DIFFERENT_SIGNAL",
        expected_outcome="ESCALATE",
        actual_outcome="ESCALATE",
        expected_isolation_level="FULL",
        actual_isolation_level="FULL",
        status=SimulationOutcomeStatus.FAIL
    )
    eval_res = SimulationEvaluator.evaluate_result(res)
    assert eval_res["is_passed"] is False
    assert eval_res["status"] == SimulationOutcomeStatus.FAIL
    assert len(eval_res["mismatches"]) >= 1
    assert "Signal mismatch" in eval_res["mismatches"][0]


def test_invalid_scenario_configuration_handling():
    registry = ScenarioRegistry(include_defaults=False)
    with pytest.raises(ValueError, match="Invalid scenario or missing scenario_id"):
        registry.register_scenario(None)


# =====================================================================
# 6. REPORT GENERATION TESTS
# =====================================================================

def test_audit_report_generation():
    executor = SimulationExecutor()
    res1 = executor.execute_scenario("SCENARIO-CAPABILITY-ESCALATION", tenant_id="t1", agent_id="a1")
    res2 = executor.execute_scenario("SCENARIO-CONTAINMENT-ESCALATION", tenant_id="t1", agent_id="a1")

    report = SimulationReportGenerator.generate_report("t1", "a1", [res1, res2])
    assert report.scenario_count == 2
    assert report.pass_count == 2
    assert report.fail_count == 0
    assert report.summary["all_passed"] is True
    assert report.report_id.startswith("sim_rpt_")


# =====================================================================
# 7. PHASE 27 INTEGRATION COMPATIBILITY
# =====================================================================

def test_agentshield_facade_simulation_integration():
    shield = AgentShield()
    assert hasattr(shield, "simulation_executor")
    assert isinstance(shield.simulation_executor, SimulationExecutor)

    res = shield.simulation_executor.execute_scenario("SCENARIO-RUNTIME-DRIFT", tenant_id="facade_t", agent_id="facade_a")
    assert res.status == SimulationOutcomeStatus.PASS
    assert res.actual_outcome == "ESCALATE"


def test_expected_actual_match_evaluation():
    res = SimulationResult(
        scenario_id="SCENARIO-BEHAVIORAL-RISK",
        expected_signal="BEHAVIOR_PATTERN_MATCH",
        actual_signal="BEHAVIOR_PATTERN_MATCH",
        expected_outcome="ESCALATE",
        actual_outcome="ESCALATE",
        expected_isolation_level="FULL",
        actual_isolation_level="FULL",
        status=SimulationOutcomeStatus.PASS
    )
    eval_res = SimulationEvaluator.evaluate_result(res)
    assert eval_res["is_passed"] is True
    assert eval_res["status"] == SimulationOutcomeStatus.PASS
    assert len(eval_res["mismatches"]) == 0


def test_safety_boundary_no_subprocess_or_network():
    executor = SimulationExecutor()
    res = executor.execute_scenario("SCENARIO-CONTAINMENT-ESCALATION", tenant_id="safe_t", agent_id="safe_a")
    assert res.metadata.get("simulation_only") is True
    for step in res.step_results:
        assert step.event.simulation_only is True
        # Safety invariant: payload contains no subprocess / command strings
        assert "subprocess" not in str(step.event.payload).lower()
        assert "os.system" not in str(step.event.payload).lower()

