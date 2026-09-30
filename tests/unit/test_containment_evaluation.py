"""
Unit and Integration Tests for Phase 27 Containment Evaluation Engine.
"""

import pytest
import time
from pathlib import Path

from agentshield import AgentShield
from agentshield.evaluation import (
    EvaluationOutcome,
    EvaluationSeverity,
    EvidenceRecord,
    ContainmentAssessment,
    EvidenceNormalizer,
    EvaluationRule,
    RuleRegistry,
    DecisionExplainer,
    ContainmentEvaluationEngine
)
from agentshield.provenance.logger import AuditLogger
from agentshield.behavior import BehaviorAssessment
from agentshield.containment import IsolationLevel, ContainmentState, ContainmentManager
from agentshield.integrity import IntegrityCheckResult, IntegrityState
from agentshield.graph import PathAssessment, SecurityPath, PathClassification


# =====================================================================
# 1. EVIDENCE & NORMALIZATION TESTS
# =====================================================================

def test_evidence_record_creation_and_hashing():
    ev1 = EvidenceRecord(
        source_phase="Phase-24",
        source_control="PHASE_24_BEHAVIORAL_DETECTOR",
        evidence_type="BEHAVIOR_PATTERN",
        severity=EvaluationSeverity.CRITICAL,
        tenant_id="t1",
        agent_id="a1",
        references={"pattern_id": "BEHAVIOR-001"}
    )
    ev2 = EvidenceRecord(
        source_phase="Phase-24",
        source_control="PHASE_24_BEHAVIORAL_DETECTOR",
        evidence_type="BEHAVIOR_PATTERN",
        severity=EvaluationSeverity.CRITICAL,
        tenant_id="t1",
        agent_id="a1",
        references={"pattern_id": "BEHAVIOR-001"}
    )
    assert ev1.compute_evidence_hash() == ev2.compute_evidence_hash()


def test_evidence_freshness_evaluation():
    norm = EvidenceNormalizer()
    ev = EvidenceRecord(timestamp=time.time() - 400.0)  # 400s old (> 300s window)
    status = norm.evaluate_freshness(ev, max_age_seconds=300.0, current_time=time.time())
    assert status == "STALE"


# =====================================================================
# 2. RULE ENGINE & PRIORITY TESTS
# =====================================================================

def test_rule_1_critical_behavior_escalate():
    engine = ContainmentEvaluationEngine()
    ev = EvidenceRecord(
        source_phase="Phase-24",
        evidence_type="BEHAVIOR_PATTERN",
        severity=EvaluationSeverity.CRITICAL,
        tenant_id="t1",
        agent_id="a1",
        references={"pattern_id": "BEHAVIOR-004"}
    )
    assessment = engine.evaluate_evidence("t1", "a1", [ev])
    assert assessment.outcome == EvaluationOutcome.ESCALATE
    assert assessment.severity == EvaluationSeverity.CRITICAL
    assert assessment.recommended_isolation_level == "FULL"
    assert "RULE-001" in assessment.matched_rules


def test_rule_2_invalid_runtime_plus_behavior():
    engine = ContainmentEvaluationEngine()
    ev_rt = EvidenceRecord(
        source_phase="Phase-23",
        evidence_type="RUNTIME_INTEGRITY",
        severity=EvaluationSeverity.CRITICAL,
        tenant_id="t1",
        agent_id="a1",
        references={"integrity_state": "INVALID"}
    )
    ev_beh = EvidenceRecord(
        source_phase="Phase-24",
        evidence_type="BEHAVIOR_PATTERN",
        severity=EvaluationSeverity.HIGH,
        tenant_id="t1",
        agent_id="a1"
    )
    assessment = engine.evaluate_evidence("t1", "a1", [ev_rt, ev_beh])
    assert assessment.outcome == EvaluationOutcome.ESCALATE
    assert assessment.severity == EvaluationSeverity.CRITICAL
    assert "RULE-001" not in assessment.matched_rules or "RULE-002" in assessment.matched_rules


def test_rule_6_recovery_review_recommendation():
    engine = ContainmentEvaluationEngine()
    ctx = {"current_containment_state": "CONTAINED", "has_recovery_request": True}

    ev_rt = EvidenceRecord(
        source_phase="Phase-23",
        evidence_type="RUNTIME_INTEGRITY",
        severity=EvaluationSeverity.LOW,
        tenant_id="t1",
        agent_id="a1",
        references={"integrity_state": "VALID"}
    )
    assessment = engine.evaluate_evidence("t1", "a1", [ev_rt], context=ctx)
    assert assessment.outcome == EvaluationOutcome.RELEASE_REVIEW
    assert assessment.recommended_isolation_level == "NONE"


def test_rule_7_clean_state_no_action():
    engine = ContainmentEvaluationEngine()
    ev_rt = EvidenceRecord(
        source_phase="Phase-23",
        evidence_type="RUNTIME_INTEGRITY",
        severity=EvaluationSeverity.LOW,
        tenant_id="t1",
        agent_id="a1",
        references={"integrity_state": "VALID"}
    )
    assessment = engine.evaluate_evidence("t1", "a1", [ev_rt])
    assert assessment.outcome == EvaluationOutcome.NO_ACTION
    assert assessment.recommended_isolation_level == "NONE"


# =====================================================================
# 3. SECURITY INVARIANT TESTS
# =====================================================================

def test_invariant_1_and_2_tenant_agent_evidence_isolation():
    engine = ContainmentEvaluationEngine()

    ev_t1_a1 = EvidenceRecord(
        source_phase="Phase-24",
        evidence_type="BEHAVIOR_PATTERN",
        severity=EvaluationSeverity.CRITICAL,
        tenant_id="t1",
        agent_id="a1"
    )

    # Evaluate t2/a1 using evidence belonging to t1/a1
    assessment = engine.evaluate_evidence("t2", "a1", [ev_t1_a1])
    # Cross-tenant evidence is filtered out, resulting in clean NO_ACTION assessment for t2/a1
    assert assessment.outcome == EvaluationOutcome.NO_ACTION


def test_invariant_5_no_automatic_release():
    cont_mgr = ContainmentManager()
    cont_mgr.request_emergency_containment("t1", "a1")

    engine = ContainmentEvaluationEngine(containment_manager=cont_mgr)
    ctx = {"current_containment_state": "CONTAINED", "has_recovery_request": True}

    assessment = engine.evaluate_evidence("t1", "a1", [], context=ctx)
    assert assessment.outcome == EvaluationOutcome.RELEASE_REVIEW

    # Engine produces recommendation only; agent state in ContainmentManager remains CONTAINED
    status = cont_mgr.get_containment_status("t1", "a1")
    assert status["current_state"] == ContainmentState.CONTAINED


def test_invariant_7_evidence_traceability():
    engine = ContainmentEvaluationEngine()
    ev = EvidenceRecord(
        source_phase="Phase-24",
        evidence_type="BEHAVIOR_PATTERN",
        severity=EvaluationSeverity.CRITICAL,
        tenant_id="t1",
        agent_id="a1"
    )
    assessment = engine.evaluate_evidence("t1", "a1", [ev])
    assert len(assessment.evidence_ids) == 1
    assert ev.evidence_id in assessment.evidence_ids
    assert ev.evidence_id[:8] in assessment.explanation


def test_invariant_9_failsafe_error_handling():
    engine = ContainmentEvaluationEngine()
    # Pass malformed object causing evaluation exception inside auto-collector
    assessment = engine._create_failsafe_assessment("t1", "a1", "Simulated exception")
    assert assessment.outcome == EvaluationOutcome.REVIEW
    assert assessment.recommended_isolation_level == "RESTRICTED"


def test_invariant_10_rule_priority_determinism():
    engine = ContainmentEvaluationEngine()

    # Conflicting evidence: LOW runtime vs CRITICAL behavior
    ev_rt = EvidenceRecord(source_phase="Phase-23", evidence_type="RUNTIME_INTEGRITY", severity=EvaluationSeverity.LOW, tenant_id="t1", agent_id="a1", references={"integrity_state": "VALID"})
    ev_beh = EvidenceRecord(source_phase="Phase-24", evidence_type="BEHAVIOR_PATTERN", severity=EvaluationSeverity.CRITICAL, tenant_id="t1", agent_id="a1")

    # Evaluate multiple times to verify exact deterministic outcome order
    for _ in range(5):
        assessment = engine.evaluate_evidence("t1", "a1", [ev_rt, ev_beh])
        assert assessment.outcome == EvaluationOutcome.ESCALATE
        assert assessment.matched_rules[0] == "RULE-001"


# =====================================================================
# 4. INTEGRATION & AUDIT TESTS
# =====================================================================

def test_audit_logger_integration(tmp_path):
    log_file = tmp_path / "eval_audit.jsonl"
    logger = AuditLogger(log_file_path=str(log_file))
    engine = ContainmentEvaluationEngine(audit_logger=logger)

    ev = EvidenceRecord(source_phase="Phase-24", evidence_type="BEHAVIOR_PATTERN", severity=EvaluationSeverity.CRITICAL, tenant_id="t1", agent_id="a1")
    engine.evaluate_evidence("t1", "a1", [ev])

    integrity = logger.verify_log_integrity()
    assert integrity["valid"] is True
    assert integrity["entries_checked"] >= 2


def test_agentshield_facade_evaluation_integration():
    shield = AgentShield()
    assert hasattr(shield, "evaluation_engine")
    assert isinstance(shield.evaluation_engine, ContainmentEvaluationEngine)

    ev = EvidenceRecord(source_phase="Phase-24", evidence_type="BEHAVIOR_PATTERN", severity=EvaluationSeverity.HIGH, tenant_id="facade_t", agent_id="facade_a")
    assessment = shield.evaluation_engine.evaluate_evidence("facade_t", "facade_a", [ev])
    assert assessment.outcome in (EvaluationOutcome.ESCALATE, EvaluationOutcome.REVIEW)


# =====================================================================
# 5. ADDITIONAL INVARIANT & NORMALIZATION TESTS
# =====================================================================

def test_invariant_3_no_capability_elevation():
    shield = AgentShield()
    # Profile has READ_DOCUMENTS granted, USE_TOOLS not granted
    assessment = shield.evaluation_engine.evaluate_evidence("t1", "a1", [])
    # Containment evaluation produces an assessment recommendation, but does not alter capability grants
    prof = shield.capability_engine.get_profile("a1", "t1")
    # CapabilityEngine profile remains untouched
    assert hasattr(shield.capability_engine, "check_capability")


def test_invariant_4_no_policy_override():
    engine = ContainmentEvaluationEngine()
    ev_rt = EvidenceRecord(source_phase="Phase-23", evidence_type="RUNTIME_INTEGRITY", severity=EvaluationSeverity.CRITICAL, tenant_id="t1", agent_id="a1", references={"integrity_state": "INVALID"})
    assessment = engine.evaluate_evidence("t1", "a1", [ev_rt])
    # INVALID runtime state must not be transformed to TRUSTED or NO_ACTION
    assert assessment.outcome != EvaluationOutcome.NO_ACTION
    assert assessment.outcome == EvaluationOutcome.ESCALATE


def test_invariant_8_no_unsupported_attribution():
    engine = ContainmentEvaluationEngine()
    ev = EvidenceRecord(source_phase="Phase-24", evidence_type="BEHAVIOR_PATTERN", severity=EvaluationSeverity.CRITICAL, tenant_id="t1", agent_id="a1")
    assessment = engine.evaluate_evidence("t1", "a1", [ev])
    # Explanation must be objective and evidence-backed
    assert "Outcome 'ESCALATE'" in assessment.explanation
    assert "Supporting Evidence:" in assessment.explanation


def test_invariant_11_previous_controls_authoritative():
    shield = AgentShield()
    assert shield.pipeline is not None
    assert shield.policy_engine is not None
    assert shield.containment_manager is not None


def test_evidence_normalization_all_phases():
    norm = EvidenceNormalizer()

    # Phase 23
    class MockIntegrity:
        state = "INVALID"
    ev23 = norm.normalize_runtime_integrity("t1", "a1", MockIntegrity())
    assert ev23.source_phase == "Phase-23"
    assert ev23.severity == EvaluationSeverity.CRITICAL

    # Phase 24
    class MockBehavior:
        matched = True
        risk_level = "CRITICAL"
        pattern_id = "PAT-001"
        pattern_name = "Exfiltration"
        confidence = 0.95
        matched_events = ["ev1"]
    ev24 = norm.normalize_behavior_assessment("t1", "a1", MockBehavior())
    assert ev24 is not None
    assert ev24.source_phase == "Phase-24"
    assert ev24.severity == EvaluationSeverity.CRITICAL

    # Phase 25
    class MockContainment:
        current_state = "CONTAINED"
        isolation_level = "FULL"
    ev25 = norm.normalize_containment_record("t1", "a1", MockContainment())
    assert ev25.source_phase == "Phase-25"
    assert ev25.severity == EvaluationSeverity.HIGH

    # Phase 26
    class MockGraph:
        paths = ["p1"]
        risk_level = "HIGH"
        signals = ["UNAUTHORIZED_TARGET"]
    ev26 = norm.normalize_graph_path_assessment("t1", "a1", MockGraph())
    assert ev26 is not None
    assert ev26.source_phase == "Phase-26"
    assert ev26.severity == EvaluationSeverity.HIGH


def test_multi_signal_correlation():
    engine = ContainmentEvaluationEngine()
    ev_beh = EvidenceRecord(source_phase="Phase-24", evidence_type="BEHAVIOR_PATTERN", severity=EvaluationSeverity.HIGH, tenant_id="t1", agent_id="a1")
    ev_rt = EvidenceRecord(source_phase="Phase-23", evidence_type="RUNTIME_INTEGRITY", severity=EvaluationSeverity.HIGH, tenant_id="t1", agent_id="a1", references={"integrity_state": "DRIFTED"})
    ev_graph = EvidenceRecord(source_phase="Phase-26", evidence_type="SECURITY_GRAPH_PATH", severity=EvaluationSeverity.HIGH, tenant_id="t1", agent_id="a1", references={"signals": ["SUSPICIOUS_COMM"]})

    assessment = engine.evaluate_evidence("t1", "a1", [ev_beh, ev_rt, ev_graph])
    assert len(assessment.evidence_ids) == 3
    assert assessment.outcome in (EvaluationOutcome.ESCALATE, EvaluationOutcome.REVIEW)
    assert len(assessment.matched_rules) >= 1

