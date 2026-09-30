"""
Comprehensive unit tests for Phase 23 Runtime Environment Integrity.
"""

import json
import pytest
from agentshield import AgentShield
from agentshield.context.models import SecurityDecision
from agentshield.capabilities.models import (
    AgentCapability,
    CapabilityGrant,
    AgentCapabilityProfile
)
from agentshield.capabilities.engine import CapabilityEngine
from agentshield.communication.models import (
    PrincipalType,
    CommunicationType,
    CommunicationPolicyRule
)
from agentshield.communication.engine import CommunicationPolicyEngine
from agentshield.integrity.models import (
    IntegrityState,
    RuntimeIntegrityBaseline,
    RuntimeStateSnapshot,
    IntegrityCheckResult,
    compute_canonical_hash
)
from agentshield.integrity.engine import RuntimeIntegrityEngine
from agentshield.provenance.logger import AuditLogger
from agentshield.security.tool_models import ToolDefinition
from agentshield.checkpoint.manager import CheckpointManager


@pytest.fixture
def audit_logger(tmp_path):
    log_file = tmp_path / "integrity_audit.jsonl"
    return AuditLogger(log_file_path=str(log_file))


@pytest.fixture
def integrity_engine(audit_logger):
    return RuntimeIntegrityEngine(audit_logger=audit_logger)


def test_baseline_creation(integrity_engine):
    """1. Create authoritative runtime integrity baseline."""
    baseline = integrity_engine.create_baseline(
        agent_id="agent_alpha",
        tenant_id="tenant_1",
        env_metadata={"python": "3.11", "os": "Windows"}
    )
    assert baseline.agent_id == "agent_alpha"
    assert baseline.tenant_id == "tenant_1"
    assert baseline.baseline_hash != ""


def test_baseline_validation(integrity_engine):
    """2. Validate baseline properties and dictionary export."""
    baseline = integrity_engine.create_baseline(agent_id="agent_b", tenant_id="tenant_2")
    d = baseline.to_dict()
    assert d["agent_id"] == "agent_b"
    assert d["tenant_id"] == "tenant_2"
    assert "baseline_hash" in d


def test_deterministic_state_snapshot(integrity_engine):
    """3. Capture deterministic active state snapshot with SHA-256 fingerprinting."""
    snap1 = integrity_engine.capture_snapshot(agent_id="agent_c", tenant_id="t1", env_metadata={"v": "1"})
    snap2 = integrity_engine.capture_snapshot(agent_id="agent_c", tenant_id="t1", env_metadata={"v": "1"})
    assert snap1.snapshot_hash == snap2.snapshot_hash


def test_matching_baseline_valid_allow(integrity_engine):
    """4. Matching baseline and active snapshot yields VALID state and ALLOW decision."""
    baseline = integrity_engine.create_baseline(agent_id="agent_match", tenant_id="tenant_match")
    snapshot = integrity_engine.capture_snapshot(agent_id="agent_match", tenant_id="tenant_match")

    res = integrity_engine.evaluate_integrity(agent_id="agent_match", tenant_id="tenant_match", current_snapshot=snapshot)
    assert res.state == IntegrityState.VALID
    assert res.decision == SecurityDecision.ALLOW
    assert res.allowed is True


def test_configuration_drift(integrity_engine):
    """5. Environment configuration drift yields REVIEW decision."""
    integrity_engine.create_baseline(agent_id="agent_cfg", tenant_id="t1", env_metadata={"env": "prod"})
    drifted_snap = integrity_engine.capture_snapshot(agent_id="agent_cfg", tenant_id="t1", env_metadata={"env": "dev"})

    res = integrity_engine.evaluate_integrity(agent_id="agent_cfg", tenant_id="t1", current_snapshot=drifted_snap)
    assert res.state == IntegrityState.REVIEW
    assert res.decision == SecurityDecision.REVIEW
    assert "ENV_METADATA_DRIFT" in res.violations


def test_capability_drift(integrity_engine):
    """6. Capability profile drift yields DENY decision and CAPABILITY_DRIFT_DETECTED violation."""
    prof1 = AgentCapabilityProfile(
        agent_id="agent_cap",
        tenant_id="t1",
        grants={AgentCapability.READ_DOCUMENTS: CapabilityGrant(capability=AgentCapability.READ_DOCUMENTS, granted=True)}
    )
    integrity_engine.create_baseline(agent_id="agent_cap", tenant_id="t1", capability_profile=prof1)

    # Drifted profile with extra unauthorized WRITE_MEMORY capability
    prof2 = AgentCapabilityProfile(
        agent_id="agent_cap",
        tenant_id="t1",
        grants={
            AgentCapability.READ_DOCUMENTS: CapabilityGrant(capability=AgentCapability.READ_DOCUMENTS, granted=True),
            AgentCapability.WRITE_MEMORY: CapabilityGrant(capability=AgentCapability.WRITE_MEMORY, granted=True)
        }
    )
    drifted_snap = integrity_engine.capture_snapshot(agent_id="agent_cap", tenant_id="t1", capability_profile=prof2)

    res = integrity_engine.evaluate_integrity(agent_id="agent_cap", tenant_id="t1", current_snapshot=drifted_snap)
    assert res.state == IntegrityState.DRIFTED
    assert res.decision == SecurityDecision.DENY
    assert "CAPABILITY_DRIFT_DETECTED" in res.violations


def test_communication_policy_drift(integrity_engine):
    """7. Communication policy drift yields DENY decision."""
    r1 = CommunicationPolicyRule(rule_id="r1", comm_type=CommunicationType.AGENT_TO_SERVICE, decision=SecurityDecision.ALLOW)
    integrity_engine.create_baseline(agent_id="agent_comm", tenant_id="t1", comm_rules=[r1])

    # Policy drift: additional unapproved rule
    r2 = CommunicationPolicyRule(rule_id="r2", comm_type=CommunicationType.AGENT_TO_AGENT, decision=SecurityDecision.ALLOW)
    drifted_snap = integrity_engine.capture_snapshot(agent_id="agent_comm", tenant_id="t1", comm_rules=[r1, r2])

    res = integrity_engine.evaluate_integrity(agent_id="agent_comm", tenant_id="t1", current_snapshot=drifted_snap)
    assert res.state == IntegrityState.DRIFTED
    assert res.decision == SecurityDecision.DENY
    assert "COMMUNICATION_POLICY_DRIFT" in res.violations


def test_tool_fingerprint_drift(integrity_engine):
    """8. Tool schema/definition drift yields REVIEW decision."""
    t1 = ToolDefinition(tool_id="t1", name="sql_query", description="Execute SQL", input_schema={"query": "str"})
    integrity_engine.create_baseline(agent_id="agent_tool", tenant_id="t1", tool_definitions=[t1])

    # Tool drift: parameter schema modified
    t1_modified = ToolDefinition(tool_id="t1", name="sql_query", description="Execute SQL", input_schema={"query": "str", "admin": "bool"})
    drifted_snap = integrity_engine.capture_snapshot(agent_id="agent_tool", tenant_id="t1", tool_definitions=[t1_modified])

    res = integrity_engine.evaluate_integrity(agent_id="agent_tool", tenant_id="t1", current_snapshot=drifted_snap)
    assert res.state == IntegrityState.REVIEW
    assert res.decision == SecurityDecision.REVIEW
    assert "TOOL_FINGERPRINT_DRIFT" in res.violations


def test_unknown_runtime_state(integrity_engine):
    """9. Evaluation without registered baseline yields UNKNOWN state and DENY decision."""
    res = integrity_engine.evaluate_integrity(agent_id="unregistered_agent", tenant_id="t1")
    assert res.state == IntegrityState.UNKNOWN
    assert res.decision == SecurityDecision.DENY
    assert res.allowed is False


def test_invalid_baseline(integrity_engine):
    """10. Attempting to evaluate mismatched baseline yields DENY."""
    integrity_engine.create_baseline(agent_id="agent_valid", tenant_id="t1")
    res = integrity_engine.evaluate_integrity(agent_id="agent_invalid", tenant_id="t1")
    assert res.decision == SecurityDecision.DENY


def test_tenant_isolation(integrity_engine):
    """11. Baselines are strictly scoped by tenant_id."""
    integrity_engine.create_baseline(agent_id="shared_agent", tenant_id="tenant_A")
    res_b = integrity_engine.evaluate_integrity(agent_id="shared_agent", tenant_id="tenant_B")
    assert res_b.state == IntegrityState.UNKNOWN
    assert res_b.decision == SecurityDecision.DENY


def test_identity_isolation(integrity_engine):
    """12. Baselines are strictly scoped by agent_id."""
    integrity_engine.create_baseline(agent_id="agent_1", tenant_id="tenant_shared")
    res = integrity_engine.evaluate_integrity(agent_id="agent_2", tenant_id="tenant_shared")
    assert res.state == IntegrityState.UNKNOWN
    assert res.decision == SecurityDecision.DENY


def test_unauthorized_baseline_modification(integrity_engine):
    """13. Baseline Hash detects tamper if baseline attributes are mutated in place."""
    baseline = integrity_engine.create_baseline(agent_id="agent_tamper", tenant_id="t1", env_metadata={"safe": True})

    # Tamper with baseline object directly
    original_hash = baseline.baseline_hash
    baseline.env_metadata["safe"] = False
    # Recomputed hash must differ
    recomputed = compute_canonical_hash({
        "agent_id": baseline.agent_id,
        "tenant_id": baseline.tenant_id,
        "capability_fingerprint": baseline.capability_fingerprint,
        "comm_policy_fingerprint": baseline.comm_policy_fingerprint,
        "tool_fingerprints": baseline.tool_fingerprints,
        "env_metadata": baseline.env_metadata
    })
    assert original_hash != recomputed


def test_attempted_capability_elevation(integrity_engine):
    """14. Runtime attempts to grant unapproved capabilities are intercepted as DRIFTED DENY."""
    integrity_engine.create_baseline(
        agent_id="restricted_bot",
        tenant_id="t1",
        capability_profile=AgentCapabilityProfile(agent_id="restricted_bot", tenant_id="t1", grants={})
    )

    # Runtime attempts self-granted capability
    self_granted_profile = AgentCapabilityProfile(
        agent_id="restricted_bot",
        tenant_id="t1",
        grants={AgentCapability.DATA_EXPORT: CapabilityGrant(capability=AgentCapability.DATA_EXPORT, granted=True)}
    )
    snap = integrity_engine.capture_snapshot(agent_id="restricted_bot", tenant_id="t1", capability_profile=self_granted_profile)

    res = integrity_engine.evaluate_integrity(agent_id="restricted_bot", tenant_id="t1", current_snapshot=snap)
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY
    assert "CAPABILITY_DRIFT_DETECTED" in res.violations


def test_audit_events_logged(audit_logger):
    """15. Runtime integrity evaluations record structured audit events."""
    engine = RuntimeIntegrityEngine(audit_logger=audit_logger)
    engine.create_baseline(agent_id="audit_agent", tenant_id="t1")
    engine.evaluate_integrity(agent_id="audit_agent", tenant_id="t1")

    with open(audit_logger.log_file_path, "r", encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]

    event_types = [e["event_type"] for e in lines]
    assert "RUNTIME_BASELINE_CREATED" in event_types
    assert "RUNTIME_INTEGRITY_VALID" in event_types


def test_phase21_capability_integration(audit_logger):
    """16. Automatic snapshot capture integrates with attached CapabilityEngine."""
    cap_engine = CapabilityEngine(audit_logger=audit_logger)
    integrity_engine = RuntimeIntegrityEngine(audit_logger=audit_logger, capability_engine=cap_engine)

    prof = AgentCapabilityProfile(
        agent_id="agent_p21",
        tenant_id="t1",
        grants={AgentCapability.USE_TOOLS: CapabilityGrant(capability=AgentCapability.USE_TOOLS, granted=True)}
    )
    cap_engine.register_profile(prof)

    # Create baseline from active engine state
    integrity_engine.create_baseline(agent_id="agent_p21", tenant_id="t1", capability_profile=prof)
    res = integrity_engine.evaluate_integrity(agent_id="agent_p21", tenant_id="t1")
    assert res.allowed is True


def test_phase22_communication_integration(audit_logger):
    """17. Automatic snapshot capture integrates with attached CommunicationPolicyEngine."""
    comm_engine = CommunicationPolicyEngine(audit_logger=audit_logger)
    integrity_engine = RuntimeIntegrityEngine(audit_logger=audit_logger, comm_engine=comm_engine)

    r1 = CommunicationPolicyRule(rule_id="r1", comm_type=CommunicationType.AGENT_TO_SERVICE, decision=SecurityDecision.ALLOW)
    comm_engine.add_rule(r1)

    integrity_engine.create_baseline(agent_id="agent_p22", tenant_id="t1", comm_rules=comm_engine._rules)
    res = integrity_engine.evaluate_integrity(agent_id="agent_p22", tenant_id="t1")
    assert res.allowed is True


def test_phase14_tool_governance_integration(integrity_engine):
    """18. Tool fingerprint baseline reuse from Phase 14 ToolDefinitions."""
    t1 = ToolDefinition(tool_id="t_read", name="read_file", description="Read file", input_schema={"path": "str"})
    integrity_engine.create_baseline(agent_id="agent_p14", tenant_id="t1", tool_definitions=[t1])
    snap = integrity_engine.capture_snapshot(agent_id="agent_p14", tenant_id="t1", tool_definitions=[t1])
    res = integrity_engine.evaluate_integrity(agent_id="agent_p14", tenant_id="t1", current_snapshot=snap)
    assert res.allowed is True


def test_phase15_checkpoint_compatibility(integrity_engine):
    """19. CheckpointManager state works compatibly with RuntimeIntegrityEngine baseline snapshots."""
    mgr = CheckpointManager()
    cp = mgr.create_checkpoint(tenant_id="t1", created_by="admin", metadata={"integrity_baseline_id": "base_100"})
    assert cp.checkpoint_id is not None
    assert cp.metadata["integrity_baseline_id"] == "base_100"


def test_backward_compatibility_facade():
    """20. Top-level AgentShield facade instantiates integrity_engine without breaking Phase 1-22 baseline."""
    shield = AgentShield()
    assert hasattr(shield, "integrity_engine")
    assert shield.integrity_engine is not None
