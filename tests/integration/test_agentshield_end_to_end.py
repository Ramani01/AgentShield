"""
Phase 30: End-to-End System Integration Test Suite for AgentShield 2.0.
Validates cross-phase security pipeline integration across Phases 1-29.
"""

import pytest
import time
from agentshield import AgentShield
from agentshield.capabilities.models import AgentCapability, CapabilityGrant, AgentCapabilityProfile, CapabilityCheckRequest
from agentshield.communication.models import CommunicationRequest, CommunicationPrincipal, PrincipalType, CommunicationType
from agentshield.evaluation import (
    EvidenceRecord,
    EvaluationSeverity,
    EvaluationOutcome,
    ContainmentEvaluationEngine
)
from agentshield.simulation import SimulationOutcomeStatus, ScenarioRegistry as SimRegistry
from agentshield.benchmark import BenchmarkScenarioRegistry, BenchmarkReporter
from agentshield.containment import ContainmentState


# =====================================================================
# 1. PUBLIC FACADE & INITIALIZATION TESTS
# =====================================================================

def test_agentshield_facade_complete_initialization():
    """Verify AgentShield facade initializes all 9 core security engines."""
    shield = AgentShield()
    assert hasattr(shield, "pipeline")
    assert hasattr(shield, "policy_engine")
    assert hasattr(shield, "capability_engine")
    assert hasattr(shield, "communication_engine")
    assert hasattr(shield, "integrity_engine")
    assert hasattr(shield, "behavior_engine")
    assert hasattr(shield, "containment_manager")
    assert hasattr(shield, "graph_engine")
    assert hasattr(shield, "evaluation_engine")
    assert hasattr(shield, "simulation_executor")
    assert hasattr(shield, "benchmark_runner")
    assert hasattr(shield, "adapter")


# =====================================================================
# 2. SCENARIO A: CLEAN STATE PIPELINE
# =====================================================================

def test_scenario_a_clean_state_pipeline():
    """Verify clean state produces NO_ACTION recommendation without unnecessary containment."""
    shield = AgentShield()
    ev_rt = EvidenceRecord(
        source_phase="Phase-23",
        evidence_type="RUNTIME_INTEGRITY",
        severity=EvaluationSeverity.LOW,
        tenant_id="t_clean",
        agent_id="a_clean",
        references={"integrity_state": "VALID"}
    )
    assessment = shield.evaluation_engine.evaluate_evidence("t_clean", "a_clean", [ev_rt])
    assert assessment.outcome == EvaluationOutcome.NO_ACTION
    assert assessment.recommended_isolation_level == "NONE"


# =====================================================================
# 3. SCENARIO B: CAPABILITY DENIAL PIPELINE
# =====================================================================

def test_scenario_b_capability_denial_pipeline():
    """Verify unauthorized capability request is denied by Phase 21 without elevation."""
    shield = AgentShield()
    prof = AgentCapabilityProfile(
        agent_id="a_cap",
        tenant_id="t_cap",
        grants={
            AgentCapability.READ_DOCUMENTS: CapabilityGrant(capability=AgentCapability.READ_DOCUMENTS, granted=True),
            AgentCapability.DATA_EXPORT: CapabilityGrant(capability=AgentCapability.DATA_EXPORT, granted=False)
        }
    )
    shield.capability_engine.register_profile(prof)

    cap_req = CapabilityCheckRequest(
        capability=AgentCapability.DATA_EXPORT,
        agent_id="a_cap",
        tenant_id="t_cap"
    )
    res = shield.capability_engine.check_capability(cap_req)
    assert res.allowed is False
    assert res.decision.value == "DENY"


# =====================================================================
# 4. SCENARIO C: COMMUNICATION DENIAL PIPELINE
# =====================================================================

def test_scenario_c_communication_denial_pipeline():
    """Verify unauthorized communication to external principal is denied by Phase 22."""
    shield = AgentShield()
    src = CommunicationPrincipal(principal_id="a_comm", principal_type=PrincipalType.AGENT, tenant_id="t_comm", name="Agent")
    dest = CommunicationPrincipal(principal_id="ext_service", principal_type=PrincipalType.UNKNOWN_SERVICE, tenant_id="external", name="UnknownService")

    comm_req = CommunicationRequest(source=src, destination=dest, comm_type=CommunicationType.AGENT_TO_SERVICE)
    dec = shield.communication_engine.evaluate_communication(comm_req)
    assert dec.allowed is False
    assert dec.decision.value == "DENY"


# =====================================================================
# 5. SCENARIO D: INVALID RUNTIME INTEGRITY PIPELINE
# =====================================================================

def test_scenario_d_invalid_runtime_pipeline():
    """Verify INVALID runtime integrity produces ESCALATE recommendation in Phase 27."""
    shield = AgentShield()
    ev_rt = EvidenceRecord(
        source_phase="Phase-23",
        evidence_type="RUNTIME_INTEGRITY",
        severity=EvaluationSeverity.CRITICAL,
        tenant_id="t_rt",
        agent_id="a_rt",
        references={"integrity_state": "INVALID"}
    )
    assessment = shield.evaluation_engine.evaluate_evidence("t_rt", "a_rt", [ev_rt])
    assert assessment.outcome == EvaluationOutcome.ESCALATE
    assert assessment.recommended_isolation_level == "FULL"


# =====================================================================
# 6. SCENARIO E: CRITICAL BEHAVIORAL RISK PIPELINE
# =====================================================================

def test_scenario_e_critical_behavioral_risk_pipeline():
    """Verify CRITICAL behavioral pattern triggers ESCALATE recommendation."""
    shield = AgentShield()
    ev_beh = EvidenceRecord(
        source_phase="Phase-24",
        evidence_type="BEHAVIOR_PATTERN",
        severity=EvaluationSeverity.CRITICAL,
        tenant_id="t_beh",
        agent_id="a_beh",
        references={"pattern_id": "BEHAVIOR-004"}
    )
    assessment = shield.evaluation_engine.evaluate_evidence("t_beh", "a_beh", [ev_beh])
    assert assessment.outcome == EvaluationOutcome.ESCALATE
    assert "RULE-001" in assessment.matched_rules


# =====================================================================
# 7. SCENARIO F: COMBINED INVALID RUNTIME + CRITICAL BEHAVIOR PIPELINE
# =====================================================================

def test_scenario_f_combined_runtime_behavior_pipeline():
    """Verify multi-signal correlation of INVALID runtime and CRITICAL behavior."""
    shield = AgentShield()
    ev_rt = EvidenceRecord(source_phase="Phase-23", evidence_type="RUNTIME_INTEGRITY", severity=EvaluationSeverity.CRITICAL, tenant_id="t_comb", agent_id="a_comb", references={"integrity_state": "INVALID"})
    ev_beh = EvidenceRecord(source_phase="Phase-24", evidence_type="BEHAVIOR_PATTERN", severity=EvaluationSeverity.CRITICAL, tenant_id="t_comb", agent_id="a_comb", references={"pattern_id": "BEHAVIOR-004"})

    assessment = shield.evaluation_engine.evaluate_evidence("t_comb", "a_comb", [ev_rt, ev_beh])
    assert assessment.outcome == EvaluationOutcome.ESCALATE
    assert len(assessment.evidence_ids) == 2


# =====================================================================
# 8. SCENARIO G: SUSPICIOUS GRAPH PATH PIPELINE
# =====================================================================

def test_scenario_g_suspicious_graph_path_pipeline():
    """Verify Phase 26 graph evidence reaches evaluation without modifying graph structures."""
    shield = AgentShield()
    ev_graph = EvidenceRecord(
        source_phase="Phase-26",
        evidence_type="SECURITY_GRAPH_PATH",
        severity=EvaluationSeverity.HIGH,
        tenant_id="t_graph",
        agent_id="a_graph",
        references={"risk_level": "HIGH", "signals": ["UNAUTHORIZED_TARGET"]}
    )
    assessment = shield.evaluation_engine.evaluate_evidence("t_graph", "a_graph", [ev_graph])
    assert assessment.outcome in (EvaluationOutcome.REVIEW, EvaluationOutcome.ESCALATE)


# =====================================================================
# 9. SCENARIO H: ALREADY CONTAINED RISK PIPELINE
# =====================================================================

def test_scenario_h_already_contained_risk_pipeline():
    """Verify CONTAINED agent with ongoing risk produces MAINTAIN recommendation."""
    shield = AgentShield()
    shield.containment_manager.request_emergency_containment("t_cont", "a_cont")

    ev_beh = EvidenceRecord(
        source_phase="Phase-26",
        evidence_type="SECURITY_GRAPH_PATH",
        severity=EvaluationSeverity.HIGH,
        tenant_id="t_cont",
        agent_id="a_cont"
    )
    ctx = {"current_containment_state": "CONTAINED", "has_recovery_request": False}
    assessment = shield.evaluation_engine.evaluate_evidence("t_cont", "a_cont", [ev_beh], context=ctx)
    assert assessment.outcome == EvaluationOutcome.MAINTAIN


# =====================================================================
# 10. SCENARIO I: RECOVERY REVIEW PIPELINE
# =====================================================================

def test_scenario_i_recovery_review_pipeline():
    """Verify RELEASE_REVIEW is only a recommendation and Phase 25 state remains CONTAINED."""
    shield = AgentShield()
    shield.containment_manager.request_emergency_containment("t_rec", "a_rec")

    ev_rt = EvidenceRecord(source_phase="Phase-23", evidence_type="RUNTIME_INTEGRITY", severity=EvaluationSeverity.LOW, tenant_id="t_rec", agent_id="a_rec", references={"integrity_state": "VALID"})
    ctx = {"current_containment_state": "CONTAINED", "has_recovery_request": True}

    assessment = shield.evaluation_engine.evaluate_evidence("t_rec", "a_rec", [ev_rt], context=ctx)
    assert assessment.outcome == EvaluationOutcome.RELEASE_REVIEW

    # ContainmentManager state remains CONTAINED (no automatic release)
    status = shield.containment_manager.get_containment_status("t_rec", "a_rec")
    assert status["current_state"] == ContainmentState.CONTAINED


# =====================================================================
# 11. END-TO-END SIMULATION & BENCHMARK INTEGRATION
# =====================================================================

def test_end_to_end_simulation_and_benchmark():
    """Runs full simulation suite and benchmark runner through facade."""
    shield = AgentShield()

    # 1. Run all 7 Phase 28 simulation scenarios
    sim_reg = SimRegistry(include_defaults=True)
    for s in sim_reg.list_scenarios():
        res = shield.simulation_executor.execute_scenario(s.scenario_id, tenant_id="e2e_t", agent_id="e2e_a")
        assert res.status == SimulationOutcomeStatus.PASS

    # 2. Run Phase 29 Benchmark
    bm_results = shield.benchmark_runner.run_benchmark(iterations=2, tenant_id="e2e_t", agent_id="e2e_a")
    assert len(bm_results) == 14  # 7 scenarios * 2 iterations
    for r in bm_results:
        assert r.pass_status is True

    # 3. Generate Report
    report = BenchmarkReporter.generate_report("e2e_t", "e2e_a", bm_results)
    assert report.metrics.total_evaluations == 14
    assert report.summary["overall_status"] == "PASS"
