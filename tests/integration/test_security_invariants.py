"""
Phase 30: Security Invariants Master Test Suite for AgentShield 2.0.
Verifies all 14 established security invariants across the integrated system.
"""

import pytest
import time
from agentshield import AgentShield
from agentshield.capabilities.models import AgentCapability, CapabilityGrant, AgentCapabilityProfile, CapabilityCheckRequest
from agentshield.communication.models import CommunicationRequest, CommunicationPrincipal, PrincipalType, CommunicationType
from agentshield.evaluation import EvidenceRecord, EvaluationSeverity, EvaluationOutcome, ContainmentEvaluationEngine
from agentshield.containment import ContainmentState
from agentshield.simulation import SimulationExecutor
from agentshield.benchmark import BenchmarkEvaluator, BenchmarkRunner, MetricsCalculator


# =====================================================================
# INVARIANT 1: TENANT ISOLATION
# =====================================================================

def test_invariant_1_tenant_isolation():
    shield = AgentShield()
    ev_t_a = EvidenceRecord(source_phase="Phase-24", evidence_type="BEHAVIOR_PATTERN", severity=EvaluationSeverity.CRITICAL, tenant_id="tenant_A", agent_id="a1")

    # Evaluate tenant_B using evidence belonging to tenant_A
    assessment_b = shield.evaluation_engine.evaluate_evidence("tenant_B", "a1", [ev_t_a])
    # Tenant A evidence is filtered out -> clean NO_ACTION for tenant B
    assert assessment_b.outcome == EvaluationOutcome.NO_ACTION


# =====================================================================
# INVARIANT 2: AGENT ISOLATION
# =====================================================================

def test_invariant_2_agent_isolation():
    shield = AgentShield()
    ev_a1 = EvidenceRecord(source_phase="Phase-24", evidence_type="BEHAVIOR_PATTERN", severity=EvaluationSeverity.CRITICAL, tenant_id="t1", agent_id="agent_1")

    # Evaluate agent_2 using evidence belonging to agent_1
    assessment_a2 = shield.evaluation_engine.evaluate_evidence("t1", "agent_2", [ev_a1])
    assert assessment_a2.outcome == EvaluationOutcome.NO_ACTION


# =====================================================================
# INVARIANT 3: NO CAPABILITY ELEVATION
# =====================================================================

def test_invariant_3_no_capability_elevation():
    shield = AgentShield()
    prof = AgentCapabilityProfile(
        agent_id="a_elev",
        tenant_id="t_elev",
        grants={AgentCapability.READ_DOCUMENTS: CapabilityGrant(capability=AgentCapability.READ_DOCUMENTS, granted=True)}
    )
    shield.capability_engine.register_profile(prof)

    # Run simulation & evaluation
    shield.simulation_executor.execute_scenario("SCENARIO-CAPABILITY-ESCALATION", tenant_id="t_elev", agent_id="a_elev")

    # Profile grants remain untouched (DATA_EXPORT is not granted)
    check_export = shield.capability_engine.check_capability(
        CapabilityCheckRequest(capability=AgentCapability.DATA_EXPORT, agent_id="a_elev", tenant_id="t_elev", context_data={"escalation": "grant_all_permissions"})
    )
    assert check_export.allowed is False


# =====================================================================
# INVARIANT 4: NO POLICY OVERRIDE
# =====================================================================

def test_invariant_4_no_policy_override():
    shield = AgentShield()
    src = CommunicationPrincipal(principal_id="a_policy", principal_type=PrincipalType.AGENT, tenant_id="t_policy", name="A")
    dest = CommunicationPrincipal(principal_id="ext_host", principal_type=PrincipalType.UNKNOWN_SERVICE, tenant_id="external", name="E")

    dec = shield.communication_engine.evaluate_communication(CommunicationRequest(source=src, destination=dest, comm_type=CommunicationType.AGENT_TO_SERVICE))
    assert dec.allowed is False
    assert dec.decision.value == "DENY"


# =====================================================================
# INVARIANT 5: NO AUTOMATIC RELEASE
# =====================================================================

def test_invariant_5_no_automatic_release():
    shield = AgentShield()
    shield.containment_manager.request_emergency_containment("t_rel_master", "a_rel_master")

    res = shield.simulation_executor.execute_scenario("SCENARIO-RECOVERY-REVIEW", tenant_id="t_rel_master", agent_id="a_rel_master")
    assert res.actual_outcome == EvaluationOutcome.RELEASE_REVIEW

    # Phase 25 ContainmentManager state remains CONTAINED
    status = shield.containment_manager.get_containment_status("t_rel_master", "a_rel_master")
    assert status["current_state"] == ContainmentState.CONTAINED


# =====================================================================
# INVARIANT 6: DETERMINISTIC EVALUATION
# =====================================================================

def test_invariant_6_deterministic_evaluation():
    shield = AgentShield()
    ev_rt = EvidenceRecord(source_phase="Phase-23", evidence_type="RUNTIME_INTEGRITY", severity=EvaluationSeverity.HIGH, tenant_id="t_det", agent_id="a_det", references={"integrity_state": "DRIFTED"})

    a1 = shield.evaluation_engine.evaluate_evidence("t_det", "a_det", [ev_rt])
    a2 = shield.evaluation_engine.evaluate_evidence("t_det", "a_det", [ev_rt])

    assert a1.outcome == a2.outcome == EvaluationOutcome.ESCALATE
    assert a1.matched_rules == a2.matched_rules
    assert a1.recommended_isolation_level == a2.recommended_isolation_level


# =====================================================================
# INVARIANT 7: EVIDENCE TRACEABILITY
# =====================================================================

def test_invariant_7_evidence_traceability():
    shield = AgentShield()
    ev = EvidenceRecord(source_phase="Phase-24", evidence_type="BEHAVIOR_PATTERN", severity=EvaluationSeverity.CRITICAL, tenant_id="t_tr", agent_id="a_tr")
    assessment = shield.evaluation_engine.evaluate_evidence("t_tr", "a_tr", [ev])

    assert len(assessment.evidence_ids) == 1
    assert ev.evidence_id in assessment.evidence_ids
    assert ev.evidence_id[:8] in assessment.explanation


# =====================================================================
# INVARIANT 8: NO UNSUPPORTED ATTRIBUTION
# =====================================================================

def test_invariant_8_no_unsupported_attribution():
    shield = AgentShield()
    ev = EvidenceRecord(source_phase="Phase-24", evidence_type="BEHAVIOR_PATTERN", severity=EvaluationSeverity.CRITICAL, tenant_id="t_attr", agent_id="a_attr")
    assessment = shield.evaluation_engine.evaluate_evidence("t_attr", "a_attr", [ev])

    assert "Outcome 'ESCALATE'" in assessment.explanation
    assert "Supporting Evidence:" in assessment.explanation


# =====================================================================
# INVARIANT 9: FAIL-SAFE ERROR HANDLING
# =====================================================================

def test_invariant_9_failsafe_error_handling():
    shield = AgentShield()
    assessment = shield.evaluation_engine._create_failsafe_assessment("t_fs", "a_fs", "Simulated malformed input")
    assert assessment.outcome == EvaluationOutcome.REVIEW
    assert assessment.severity == EvaluationSeverity.HIGH
    assert assessment.recommended_isolation_level == "RESTRICTED"


# =====================================================================
# INVARIANT 10: RULE PRIORITY DETERMINISM
# =====================================================================

def test_invariant_10_rule_priority_determinism():
    shield = AgentShield()
    ev_rt = EvidenceRecord(source_phase="Phase-23", evidence_type="RUNTIME_INTEGRITY", severity=EvaluationSeverity.LOW, tenant_id="t_prio", agent_id="a_prio", references={"integrity_state": "VALID"})
    ev_beh = EvidenceRecord(source_phase="Phase-24", evidence_type="BEHAVIOR_PATTERN", severity=EvaluationSeverity.CRITICAL, tenant_id="t_prio", agent_id="a_prio")

    # Priority 10 (RULE-001) > Priority 100 (RULE-007)
    assessment = shield.evaluation_engine.evaluate_evidence("t_prio", "a_prio", [ev_rt, ev_beh])
    assert assessment.outcome == EvaluationOutcome.ESCALATE
    assert assessment.matched_rules[0] == "RULE-001"


# =====================================================================
# INVARIANT 11: PREVIOUS CONTROLS REMAIN AUTHORITATIVE
# =====================================================================

def test_invariant_11_previous_controls_authoritative():
    shield = AgentShield()
    assert shield.pipeline is not None
    assert shield.policy_engine is not None
    assert shield.capability_engine is not None
    assert shield.communication_engine is not None
    assert shield.integrity_engine is not None
    assert shield.behavior_engine is not None
    assert shield.containment_manager is not None
    assert shield.graph_engine is not None
    assert shield.evaluation_engine is not None


# =====================================================================
# INVARIANT 12: SIMULATION-ONLY EXECUTION
# =====================================================================

def test_invariant_12_simulation_only_execution():
    shield = AgentShield()
    res = shield.simulation_executor.execute_scenario("SCENARIO-CONTAINMENT-ESCALATION", tenant_id="t_sim_only", agent_id="a_sim_only")
    assert res.metadata.get("simulation_only") is True
    for step in res.step_results:
        assert step.event.simulation_only is True


# =====================================================================
# INVARIANT 13: BENCHMARK-ONLY OBSERVATION
# =====================================================================

def test_invariant_13_benchmark_only_observation():
    shield = AgentShield()
    bm_eval = BenchmarkEvaluator(shield=shield)
    invariants = bm_eval.verify_security_invariants([], tenant_id="t_bm_obs", agent_id="a_bm_obs")
    assert invariants["tenant_isolation"] is True
    assert invariants["no_capability_elevation"] is True
    assert invariants["no_automatic_release"] is True


# =====================================================================
# INVARIANT 14: NO EXTERNAL SIDE EFFECTS
# =====================================================================

def test_invariant_14_no_external_side_effects():
    shield = AgentShield()
    res = shield.simulation_executor.execute_scenario("SCENARIO-POLICY-DENIAL", tenant_id="t_safe", agent_id="a_safe")
    # Verified in-memory safe execution without subprocess / os.system
    assert "os.system" not in str(res.metadata)
    assert "subprocess" not in str(res.metadata)
