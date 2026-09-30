"""
Unit and Integration Tests for Phase 25 Agent Isolation & Emergency Containment.
"""

import pytest
import time
from pathlib import Path

from agentshield import AgentShield
from agentshield.behavior import BehaviorEventType, BehaviorAssessment
from agentshield.containment import (
    ContainmentState,
    IsolationLevel,
    InvalidStateTransitionError,
    validate_state_transition,
    ContainmentRequest,
    ContainmentRecord,
    GateDecision,
    IsolationStateManager,
    ContainmentPolicy,
    ContainmentPolicyEngine,
    ContainmentActionGate,
    ContainmentRecoveryManager,
    ContainmentManager
)
from agentshield.provenance.logger import AuditLogger
from agentshield.capabilities import CapabilityEngine
from agentshield.communication import CommunicationPolicyEngine
from agentshield.integrity import RuntimeIntegrityEngine, RuntimeStateSnapshot, IntegrityState


# =====================================================================
# 1. STATE MACHINE & TRANSITION TESTS
# =====================================================================

def test_containment_state_initial_normal():
    manager = IsolationStateManager()
    rec = manager.get_record("tenant_1", "agent_1")
    assert rec.current_state == ContainmentState.NORMAL
    assert rec.isolation_level == IsolationLevel.NONE


def test_valid_state_lifecycle():
    manager = IsolationStateManager()
    # NORMAL -> SUSPECTED
    r1 = manager.transition_state("t1", "a1", ContainmentState.SUSPECTED, IsolationLevel.MONITOR)
    assert r1.current_state == ContainmentState.SUSPECTED

    # SUSPECTED -> CONTAINED
    r2 = manager.transition_state("t1", "a1", ContainmentState.CONTAINED, IsolationLevel.FULL)
    assert r2.current_state == ContainmentState.CONTAINED

    # CONTAINED -> RECOVERY
    r3 = manager.transition_state("t1", "a1", ContainmentState.RECOVERY, IsolationLevel.RESTRICTED)
    assert r3.current_state == ContainmentState.RECOVERY

    # RECOVERY -> RELEASED
    r4 = manager.transition_state("t1", "a1", ContainmentState.RELEASED, IsolationLevel.NONE)
    assert r4.current_state == ContainmentState.RELEASED

    # RELEASED -> NORMAL
    r5 = manager.transition_state("t1", "a1", ContainmentState.NORMAL, IsolationLevel.NONE)
    assert r5.current_state == ContainmentState.NORMAL


def test_invalid_state_transition_rejection():
    manager = IsolationStateManager()
    # Cannot transition NORMAL -> RECOVERY
    with pytest.raises(InvalidStateTransitionError):
        manager.transition_state("t1", "a1", ContainmentState.RECOVERY)

    # Transition NORMAL -> CONTAINED -> RELEASED (Cannot bypass RECOVERY)
    manager.transition_state("t1", "a1", ContainmentState.CONTAINED)
    with pytest.raises(InvalidStateTransitionError):
        manager.transition_state("t1", "a1", ContainmentState.RELEASED)


# =====================================================================
# 2. TENANT & AGENT ISOLATION TESTS
# =====================================================================

def test_tenant_and_agent_isolation():
    manager = ContainmentManager()
    # Contain Tenant 1 Agent 1
    manager.request_emergency_containment(tenant_id="t1", agent_id="a1", isolation_level=IsolationLevel.FULL)

    status_t1_a1 = manager.get_containment_status("t1", "a1")
    status_t1_a2 = manager.get_containment_status("t1", "a2")
    status_t2_a1 = manager.get_containment_status("t2", "a1")

    assert status_t1_a1["current_state"] == ContainmentState.CONTAINED
    assert status_t1_a2["current_state"] == ContainmentState.NORMAL
    assert status_t2_a1["current_state"] == ContainmentState.NORMAL


def test_cross_tenant_release_rejection():
    manager = ContainmentManager()
    manager.request_emergency_containment(tenant_id="t1", agent_id="a1")

    # Initiate recovery for t1/a1
    res_rec = manager.initiate_recovery(tenant_id="t1", agent_id="a1", principal_id="admin_user")
    assert res_rec["success"] is True

    # Attempt to release t2/a1 (normal agent) using recovery
    res_rel = manager.release_containment(tenant_id="t2", agent_id="a1", principal_id="admin_user")
    assert res_rel["success"] is False
    assert "NORMAL" in res_rel["reason"] or "RECOVERY" in res_rel["reason"]


# =====================================================================
# 3. ACTION GATE TESTS
# =====================================================================

def test_action_gate_normal_state():
    manager = ContainmentManager()
    decision = manager.evaluate_action_gate(
        tenant_id="t1",
        agent_id="a1",
        action_type=BehaviorEventType.MODIFY_CONFIGURATION
    )
    assert decision.allowed is True
    assert decision.decision == "ALLOW"


def test_action_gate_restricted_isolation_level():
    manager = ContainmentManager()
    manager.request_emergency_containment(
        tenant_id="t1",
        agent_id="a1",
        isolation_level=IsolationLevel.RESTRICTED
    )

    # MODIFY_CONFIGURATION should be DENIED under RESTRICTED
    d1 = manager.evaluate_action_gate("t1", "a1", BehaviorEventType.MODIFY_CONFIGURATION)
    assert d1.allowed is False
    assert d1.decision == "DENY"

    # DATA_EXPORT should be DENIED under RESTRICTED
    d2 = manager.evaluate_action_gate("t1", "a1", BehaviorEventType.DATA_EXPORT)
    assert d2.allowed is False
    assert d2.decision == "DENY"

    # READ_DOCUMENT should be ALLOWED under RESTRICTED
    d3 = manager.evaluate_action_gate("t1", "a1", BehaviorEventType.READ_DOCUMENT)
    assert d3.allowed is True
    assert d3.decision == "ALLOW"


def test_action_gate_full_isolation_level():
    manager = ContainmentManager()
    manager.request_emergency_containment(
        tenant_id="t1",
        agent_id="a1",
        isolation_level=IsolationLevel.FULL
    )

    # Non-essential actions blocked under FULL
    for action in [
        BehaviorEventType.MODIFY_CONFIGURATION,
        BehaviorEventType.DATA_EXPORT,
        BehaviorEventType.EXTERNAL_COMMUNICATION,
        BehaviorEventType.USE_TOOL,
        BehaviorEventType.WRITE_MEMORY
    ]:
        d = manager.evaluate_action_gate("t1", "a1", action)
        assert d.allowed is False
        assert d.decision == "DENY"

    # READ_DOCUMENT permitted under FULL
    d_read = manager.evaluate_action_gate("t1", "a1", BehaviorEventType.READ_DOCUMENT)
    assert d_read.allowed is True


# =====================================================================
# 4. IDEMPOTENCY & EMERGENCY TESTS
# =====================================================================

def test_emergency_containment_idempotency():
    manager = ContainmentManager()
    r1 = manager.request_emergency_containment("t1", "a1", reason="First trigger")
    assert r1.current_state == ContainmentState.CONTAINED

    r2 = manager.request_emergency_containment("t1", "a1", reason="Second trigger")
    assert r2.current_state == ContainmentState.CONTAINED
    # State transition history should not contain duplicate entries
    assert len(r2.state_history) == 1


# =====================================================================
# 5. SECURITY INVARIANT TESTS
# =====================================================================

def test_invariant_4_self_release_blocked():
    manager = ContainmentManager()
    manager.request_emergency_containment("t1", "agent_x")
    manager.isolation_manager.transition_state("t1", "agent_x", ContainmentState.RECOVERY)

    # Agent 'agent_x' attempts self-release
    res = manager.release_containment("t1", "agent_x", principal_id="agent_x")
    assert res["success"] is False
    assert "Self-release rejected" in res["reason"]


def test_invariant_5_contained_agent_cannot_modify_policy():
    manager = ContainmentManager()
    manager.request_emergency_containment("t1", "a1", isolation_level=IsolationLevel.RESTRICTED)

    # Contained agent attempts MODIFY_CONFIGURATION action
    gate_res = manager.evaluate_action_gate("t1", "a1", BehaviorEventType.MODIFY_CONFIGURATION)
    assert gate_res.allowed is False
    assert gate_res.decision == "DENY"
    assert "cannot modify configuration" in gate_res.reason


def test_invariant_7_runtime_integrity_blocks_release():
    integrity_eng = RuntimeIntegrityEngine()

    manager = ContainmentManager(integrity_engine=integrity_eng)
    manager.request_emergency_containment("t1", "a1")
    manager.initiate_recovery("t1", "a1", principal_id="admin_governance")

    # Release attempt must be blocked when runtime integrity is UNKNOWN/INVALID (no approved baseline)
    res = manager.release_containment("t1", "a1", principal_id="admin_governance")
    assert res["success"] is False
    assert "Runtime environment integrity state" in res["reason"]


# =====================================================================
# 6. INTEGRATION & AUDIT TESTS
# =====================================================================

def test_phase_24_behavior_integration_trigger():
    manager = ContainmentManager()
    # Synthetic Phase 24 assessment with CRITICAL risk
    assessment = BehaviorAssessment(
        matched=True,
        pattern_id="BEHAVIOR-003",
        pattern_name="Configuration-to-Egress Chain",
        risk_level="CRITICAL",
        recommended_decision="DENY"
    )

    rec = manager.evaluate_behavior_and_contain("t1", "a1", assessment)
    assert rec.current_state == ContainmentState.CONTAINED
    assert rec.isolation_level == IsolationLevel.FULL


def test_audit_logger_containment_events(tmp_path):
    log_file = tmp_path / "containment_audit.jsonl"
    logger = AuditLogger(log_file_path=str(log_file))
    manager = ContainmentManager(audit_logger=logger)

    # Trigger emergency containment
    manager.request_emergency_containment("t1", "a1")
    # Gate block action
    manager.evaluate_action_gate("t1", "a1", BehaviorEventType.DATA_EXPORT)

    integrity = logger.verify_log_integrity()
    assert integrity["valid"] is True
    assert integrity["entries_checked"] >= 3


def test_agentshield_facade_containment_integration():
    shield = AgentShield()
    assert hasattr(shield, "containment_manager")
    assert isinstance(shield.containment_manager, ContainmentManager)

    rec = shield.containment_manager.request_emergency_containment(
        tenant_id="facade_t",
        agent_id="facade_a"
    )
    assert rec.current_state == ContainmentState.CONTAINED
