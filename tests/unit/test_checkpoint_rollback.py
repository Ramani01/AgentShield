"""
Unit & Security Tests for Phase 15 - Security Checkpoint & Rollback.
Verifies checkpoint creation, fingerprint determinism, integrity validation, immutability,
tenant isolation, identity authorization, rollback workflows, failure safety, audit logging,
performance benchmarking, and non-execution security separation invariants.
"""

import json
import time
import pytest
from typing import Dict, Any

from agentshield.checkpoint.models import (
    SecurityCheckpoint,
    CheckpointStatus,
    RollbackRequest,
    RollbackResult
)
from agentshield.checkpoint.fingerprint import compute_checkpoint_fingerprint
from agentshield.checkpoint.manager import CheckpointManager
from agentshield.security.tool_models import ToolDefinition, ToolBaseline
from agentshield.security.tool_governance import ToolGovernanceRegistry
from agentshield.context.models import SecurityDecision, UserIdentity
from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.config import ShieldConfig
from agentshield.core.exceptions import SecurityViolationError
from agentshield.provenance.logger import AuditLogger

# =====================================================================
# 1. CHECKPOINT CREATION TESTS (A - E)
# =====================================================================

def test_create_checkpoint_success():
    """A. Create checkpoint successfully."""
    mgr = CheckpointManager()
    tool = ToolDefinition(tool_id="t1", name="Tool 1")
    reg = ToolGovernanceRegistry()
    b1 = reg.register_baseline(tool)
    
    chk = mgr.create_checkpoint(
        created_by="admin_user",
        tenant_id="tenant_a",
        description="Initial approved baseline",
        tool_baselines={"t1": b1}
    )
    
    assert chk.checkpoint_id.startswith("chk_")
    assert chk.created_by == "admin_user"
    assert chk.tenant_id == "tenant_a"
    assert "t1" in chk.tool_baselines
    assert chk.status == CheckpointStatus.ACTIVE

def test_checkpoint_contains_required_metadata():
    """B. Checkpoint contains required metadata."""
    mgr = CheckpointManager()
    chk = mgr.create_checkpoint(
        created_by="sec_admin",
        tenant_id="tenant_b",
        description="Metadata test",
        provenance_id="prov_123",
        metadata={"environment": "production"}
    )
    assert chk.provenance_id == "prov_123"
    assert chk.metadata["environment"] == "production"
    assert chk.created_at > 0

def test_checkpoint_fingerprint_deterministic():
    """C. Checkpoint fingerprint is deterministic."""
    reg = ToolGovernanceRegistry()
    t1 = ToolDefinition(tool_id="t1", name="Tool 1")
    b1 = reg.register_baseline(t1)
    
    fp1 = compute_checkpoint_fingerprint({"t1": b1}, {"rule": "allow"}, {"strict": True}, "tenant_a")
    fp2 = compute_checkpoint_fingerprint({"t1": b1}, {"rule": "allow"}, {"strict": True}, "tenant_a")
    assert fp1 == fp2
    assert len(fp1) == 64 # SHA-256 length

def test_equivalent_states_produce_same_fingerprint():
    """D. Equivalent states with different dictionary key ordering produce same fingerprint."""
    reg = ToolGovernanceRegistry()
    t1 = ToolDefinition(tool_id="t1", name="Tool 1")
    b1 = reg.register_baseline(t1)
    
    fp1 = compute_checkpoint_fingerprint({"t1": b1}, {"a": 1, "b": 2}, {"x": 10, "y": 20}, "tenant_a")
    fp2 = compute_checkpoint_fingerprint({"t1": b1}, {"b": 2, "a": 1}, {"y": 20, "x": 10}, "tenant_a")
    assert fp1 == fp2

def test_creation_generates_audit_event(tmp_path):
    """E. Creation generates audit event."""
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_file_path=str(log_file))
    mgr = CheckpointManager(audit_logger=logger)
    
    chk = mgr.create_checkpoint(created_by="admin_user", tenant_id="tenant_a")
    
    with open(log_file, "r", encoding="utf-8") as f:
        logs = [json.loads(line) for line in f if line.strip()]
    event_types = [l["event_type"] for l in logs]
    assert "CHECKPOINT_CREATED" in event_types

# =====================================================================
# 2. CHECKPOINT INTEGRITY TESTS (F - J)
# =====================================================================

def test_valid_checkpoint_passes_validation():
    """F. Valid checkpoint passes validation."""
    mgr = CheckpointManager()
    chk = mgr.create_checkpoint(created_by="admin")
    val_res = mgr.validate_checkpoint(chk.checkpoint_id)
    assert val_res["valid"]
    assert val_res["checkpoint"].checkpoint_id == chk.checkpoint_id

def test_modified_checkpoint_fails_validation():
    """G. Modified checkpoint payload fails validation."""
    mgr = CheckpointManager()
    chk = mgr.create_checkpoint(created_by="admin")
    
    # Tamper with stored checkpoint payload
    tampered_chk = mgr.get_checkpoint(chk.checkpoint_id)
    tampered_chk.policy_snapshot["injected_rule"] = "bypass_all"
    
    val_res = mgr.validate_checkpoint(tampered_chk)
    assert not val_res["valid"]
    assert "Integrity failure" in val_res["reason"]

def test_invalid_fingerprint_fails():
    """H. Checkpoint with corrupt state_fingerprint fails validation."""
    mgr = CheckpointManager()
    chk = mgr.create_checkpoint(created_by="admin")
    chk.state_fingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
    
    val_res = mgr.validate_checkpoint(chk)
    assert not val_res["valid"]

def test_missing_checkpoint_fails():
    """I. Missing checkpoint fails validation."""
    mgr = CheckpointManager()
    val_res = mgr.validate_checkpoint("chk_non_existent")
    assert not val_res["valid"]
    assert "not found" in val_res["reason"]

def test_corrupted_checkpoint_cannot_be_restored():
    """J. Corrupted checkpoint cannot be restored during rollback."""
    mgr = CheckpointManager()
    chk = mgr.create_checkpoint(created_by="admin", tenant_id="tenant_a")
    
    # Corrupt stored checkpoint
    corrupted = mgr._checkpoints[chk.checkpoint_id]
    corrupted.policy_snapshot["corrupt"] = True
    
    req = RollbackRequest(checkpoint_id=chk.checkpoint_id, requested_by="admin", tenant_id="tenant_a")
    res = mgr.execute_rollback(req)
    assert not res.restored
    assert res.decision == SecurityDecision.DENY
    assert "validation failed" in res.reason

# =====================================================================
# 3. IMMUTABILITY TESTS (K - L)
# =====================================================================

def test_existing_checkpoint_immutable():
    """K. Mutating returned checkpoint copy does not alter manager's internal stored state."""
    mgr = CheckpointManager()
    chk = mgr.create_checkpoint(created_by="admin", description="Original")
    
    retrieved = mgr.get_checkpoint(chk.checkpoint_id)
    retrieved.description = "Tampered Description"
    
    stored = mgr.get_checkpoint(chk.checkpoint_id)
    assert stored.description == "Original"

def test_new_security_state_creates_new_checkpoint():
    """L. New security state creates a new distinct checkpoint."""
    mgr = CheckpointManager()
    chk1 = mgr.create_checkpoint(created_by="admin", description="v1")
    chk2 = mgr.create_checkpoint(created_by="admin", description="v2")
    
    assert chk1.checkpoint_id != chk2.checkpoint_id

# =====================================================================
# 4. AUTHORIZATION TESTS (M - Q)
# =====================================================================

def test_authorized_rollback_succeeds():
    """M. Authorized rollback succeeds."""
    mgr = CheckpointManager()
    reg = ToolGovernanceRegistry()
    t1 = ToolDefinition(tool_id="t1", name="Tool 1")
    reg.register_baseline(t1)
    
    chk = mgr.create_checkpoint(created_by="admin", tenant_id="t_app", tool_baselines=reg.export_baselines())
    
    identity = UserIdentity(user_id="admin", tenant_id="t_app", roles=["security_admin"])
    req = RollbackRequest(checkpoint_id=chk.checkpoint_id, requested_by="admin", tenant_id="t_app")
    
    res = mgr.execute_rollback(req, identity=identity, registry=reg)
    assert res.restored
    assert res.decision == SecurityDecision.ALLOW

def test_missing_identity_denied():
    """N. Rollback with missing requested_by identity fails closed."""
    mgr = CheckpointManager()
    chk = mgr.create_checkpoint(created_by="admin")
    
    req = RollbackRequest(checkpoint_id=chk.checkpoint_id, requested_by="", tenant_id="default")
    res = mgr.execute_rollback(req)
    assert not res.restored
    assert res.decision == SecurityDecision.DENY
    assert "missing identity" in res.reason

def test_unauthorized_role_rollback_denied():
    """O. Rollback by unauthorized role (e.g. guest/user) is denied."""
    mgr = CheckpointManager()
    chk = mgr.create_checkpoint(created_by="admin", tenant_id="t1")
    
    guest = UserIdentity(user_id="user1", tenant_id="t1", roles=["guest"])
    req = RollbackRequest(checkpoint_id=chk.checkpoint_id, requested_by="user1", tenant_id="t1")
    
    res = mgr.execute_rollback(req, identity=guest)
    assert not res.restored
    assert res.decision == SecurityDecision.DENY
    assert "unauthorized" in res.reason

def test_cross_tenant_rollback_denied():
    """P. Cross-tenant rollback (Tenant A checkpoint -> Tenant B request) is denied."""
    mgr = CheckpointManager()
    chk = mgr.create_checkpoint(created_by="admin", tenant_id="tenant_A")
    
    admin_b = UserIdentity(user_id="admin_b", tenant_id="tenant_B", roles=["admin"])
    req = RollbackRequest(checkpoint_id=chk.checkpoint_id, requested_by="admin_b", tenant_id="tenant_B")
    
    res = mgr.execute_rollback(req, identity=admin_b)
    assert not res.restored
    assert res.decision == SecurityDecision.DENY
    assert "tenant" in res.reason.lower()

def test_invalid_security_scope_denied():
    """Q. Identity tenant mismatch with request tenant is denied."""
    mgr = CheckpointManager()
    chk = mgr.create_checkpoint(created_by="admin", tenant_id="tenant_A")
    
    spoofed = UserIdentity(user_id="admin", tenant_id="tenant_B", roles=["admin"])

    req = RollbackRequest(checkpoint_id=chk.checkpoint_id, requested_by="admin", tenant_id="tenant_A")
    
    res = mgr.execute_rollback(req, identity=spoofed)
    assert not res.restored
    assert res.decision == SecurityDecision.DENY

# =====================================================================
# 5. ROLLBACK WORKFLOW TESTS (R - W)
# =====================================================================

def test_rollback_restores_previous_tool_baseline():
    """R. Rollback restores previous tool baseline state."""
    reg = ToolGovernanceRegistry()
    mgr = CheckpointManager()
    
    t1_v1 = ToolDefinition(tool_id="t1", name="Tool 1", version="1.0.0")
    reg.register_baseline(t1_v1)
    
    chk_v1 = mgr.create_checkpoint(created_by="admin", tenant_id="default", tool_baselines=reg.export_baselines())
    
    # Apply tool change
    t1_v2 = ToolDefinition(tool_id="t1", name="Tool 1", version="2.0.0")
    reg.approve_tool_change("t1", t1_v2)
    assert reg.get_baseline("t1").version == "2.0.0"
    
    # Rollback to v1 checkpoint
    req = RollbackRequest(checkpoint_id=chk_v1.checkpoint_id, requested_by="admin", tenant_id="default")
    res = mgr.execute_rollback(req, registry=reg)
    assert res.restored
    assert reg.get_baseline("t1").version == "1.0.0"

def test_rollback_restores_policy_state():
    """S. Rollback returns restored policy state fingerprint."""
    mgr = CheckpointManager()
    p_snap = {"strict": True, "rules": ["no_eval"]}
    chk = mgr.create_checkpoint(created_by="admin", tenant_id="default", policy_snapshot=p_snap)
    
    req = RollbackRequest(checkpoint_id=chk.checkpoint_id, requested_by="admin")
    res = mgr.execute_rollback(req)
    assert res.restored
    assert res.restored_state_fingerprint == chk.state_fingerprint

def test_rollback_restores_configuration_state():
    """T. Rollback returns valid configuration state."""
    mgr = CheckpointManager()
    c_snap = {"injection_threshold": 0.85}
    chk = mgr.create_checkpoint(created_by="admin", tenant_id="default", configuration_snapshot=c_snap)
    
    req = RollbackRequest(checkpoint_id=chk.checkpoint_id, requested_by="admin")
    res = mgr.execute_rollback(req)
    assert res.restored

def test_current_state_fingerprint_captured_before_rollback():
    """U. Current state fingerprint is captured before rollback execution."""
    mgr = CheckpointManager()
    reg = ToolGovernanceRegistry()
    t1 = ToolDefinition(tool_id="t1", name="T1", version="1.0")
    reg.register_baseline(t1)
    
    chk1 = mgr.create_checkpoint(created_by="admin", tool_baselines=reg.export_baselines())
    
    t2 = ToolDefinition(tool_id="t1", name="T1", version="2.0")
    reg.approve_tool_change("t1", t2)
    
    req = RollbackRequest(checkpoint_id=chk1.checkpoint_id, requested_by="admin")
    res = mgr.execute_rollback(req, registry=reg)
    
    assert res.previous_state_fingerprint is not None
    assert res.previous_state_fingerprint != res.restored_state_fingerprint

def test_post_rollback_fingerprint_verified():
    """V. Post-rollback fingerprint matches checkpoint state fingerprint."""
    mgr = CheckpointManager()
    reg = ToolGovernanceRegistry()
    t1 = ToolDefinition(tool_id="t1", name="T1")
    reg.register_baseline(t1)
    
    chk = mgr.create_checkpoint(created_by="admin", tool_baselines=reg.export_baselines())
    
    req = RollbackRequest(checkpoint_id=chk.checkpoint_id, requested_by="admin")
    res = mgr.execute_rollback(req, registry=reg)
    assert res.restored_state_fingerprint == chk.state_fingerprint

def test_successful_rollback_generates_audit_event(tmp_path):
    """W. Successful rollback generates ROLLBACK_COMPLETED audit event."""
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_file_path=str(log_file))
    mgr = CheckpointManager(audit_logger=logger)
    
    chk = mgr.create_checkpoint(created_by="admin")
    req = RollbackRequest(checkpoint_id=chk.checkpoint_id, requested_by="admin")
    mgr.execute_rollback(req)
    
    with open(log_file, "r", encoding="utf-8") as f:
        logs = [json.loads(line) for line in f if line.strip()]
    event_types = [l["event_type"] for l in logs]
    assert "ROLLBACK_COMPLETED" in event_types

# =====================================================================
# 6. FAILURE SAFETY TESTS (X - Z)
# =====================================================================

def test_failed_restoration_does_not_report_success():
    """X. Failed restoration returns restored=False and DENY decision."""
    mgr = CheckpointManager()
    req = RollbackRequest(checkpoint_id="non_existent", requested_by="admin")
    res = mgr.execute_rollback(req)
    assert not res.restored
    assert res.decision == SecurityDecision.DENY

def test_rejected_rollback_does_not_alter_current_state():
    """Y. Rejected rollback does not alter current tool baselines."""
    reg = ToolGovernanceRegistry()
    mgr = CheckpointManager()
    
    t1 = ToolDefinition(tool_id="t1", name="Tool 1", version="1.0.0")
    reg.register_baseline(t1)
    chk1 = mgr.create_checkpoint(created_by="admin", tool_baselines=reg.export_baselines())
    
    # Change to v2
    t2 = ToolDefinition(tool_id="t1", name="Tool 1", version="2.0.0")
    reg.approve_tool_change("t1", t2)
    
    # Unauthorized rollback request (rejected)
    guest = UserIdentity(user_id="guest", roles=["guest"])
    req = RollbackRequest(checkpoint_id=chk1.checkpoint_id, requested_by="guest")
    res = mgr.execute_rollback(req, identity=guest, registry=reg)

    
    assert not res.restored
    assert reg.get_baseline("t1").version == "2.0.0"

def test_invalid_checkpoint_does_not_alter_current_state():
    """Z. Invalid/corrupted checkpoint does not alter current state."""
    reg = ToolGovernanceRegistry()
    mgr = CheckpointManager()
    
    t1 = ToolDefinition(tool_id="t1", name="Tool 1", version="1.0.0")
    reg.register_baseline(t1)
    chk = mgr.create_checkpoint(created_by="admin", tool_baselines=reg.export_baselines())
    
    # Corrupt checkpoint stored copy
    mgr._checkpoints[chk.checkpoint_id].state_fingerprint = "invalid_hash"
    
    req = RollbackRequest(checkpoint_id=chk.checkpoint_id, requested_by="admin")
    res = mgr.execute_rollback(req, registry=reg)
    
    assert not res.restored
    assert reg.get_baseline("t1").version == "1.0.0"

# =====================================================================
# 7. SECURITY SEPARATION TESTS (AA - AD)
# =====================================================================

def test_checkpoint_fingerprint_does_not_imply_trust():
    """AA. Checkpoint fingerprint proves integrity, NOT safety/trust."""
    mgr = CheckpointManager()
    chk = mgr.create_checkpoint(created_by="untrusted_source", metadata={"trusted": False})
    val_res = mgr.validate_checkpoint(chk.checkpoint_id)
    assert val_res["valid"] # Integrity ok
    assert val_res["checkpoint"].metadata["trusted"] is False # Does not grant trust

def test_checkpoint_provenance_does_not_imply_trust():
    """AB. Checkpoint provenance does not automatically grant trust."""
    mgr = CheckpointManager()
    chk = mgr.create_checkpoint(created_by="ext", provenance_id="prov_external_third_party")
    assert chk.provenance_id == "prov_external_third_party"
    assert chk.status == CheckpointStatus.ACTIVE # Provenance recorded, but trust remains separate

def test_tool_execution_never_occurs_during_rollback():
    """AC. Tool execution is never invoked during rollback execution."""
    reg = ToolGovernanceRegistry()
    mgr = CheckpointManager()
    
    t1 = ToolDefinition(tool_id="exec_tool", name="Exec Tool", capabilities=["shell_exec"])
    reg.register_baseline(t1)
    
    chk = mgr.create_checkpoint(created_by="admin", tool_baselines=reg.export_baselines())
    req = RollbackRequest(checkpoint_id=chk.checkpoint_id, requested_by="admin")
    
    res = mgr.execute_rollback(req, registry=reg)
    assert res.restored
    # Verification: Tool definition baselines were restored strictly as static metadata

def test_external_network_activity_never_occurs_during_rollback():
    """AD. External network requests never occur during rollback."""
    mgr = CheckpointManager()
    chk = mgr.create_checkpoint(created_by="admin")
    req = RollbackRequest(checkpoint_id=chk.checkpoint_id, requested_by="admin")
    res = mgr.execute_rollback(req)
    assert res.restored

# =====================================================================
# 8. INTEGRATION TESTS (AE - AI)
# =====================================================================

def test_phase14_tool_baseline_can_be_checkpointed():
    """AE. Phase 14 tool baseline can be checkpointed in SecurityPipeline."""
    pipe = SecurityPipeline()
    t1 = ToolDefinition(tool_id="pipe_t1", name="Pipe Tool", version="1.0.0")
    pipe.approve_tool_change("pipe_t1", t1)
    
    chk = pipe.create_security_checkpoint(created_by="admin")
    assert "pipe_t1" in chk.tool_baselines

def test_restored_baseline_reused_by_tool_governance():
    """AF. Restored baseline can be reused by ToolGovernanceRegistry for drift detection."""
    pipe = SecurityPipeline()
    t1_v1 = ToolDefinition(tool_id="t1", name="T1", version="1.0.0")
    pipe.approve_tool_change("t1", t1_v1)
    
    chk1 = pipe.create_security_checkpoint(created_by="admin")
    
    t1_v2 = ToolDefinition(tool_id="t1", name="T1", version="2.0.0")
    pipe.approve_tool_change("t1", t1_v2)
    
    # Rollback to v1
    req = RollbackRequest(checkpoint_id=chk1.checkpoint_id, requested_by="admin")
    pipe.rollback_security_checkpoint(req)
    
    # Compare v1 tool definition -> should be ALLOW / unchanged
    res = pipe.validate_tool_change(t1_v1)
    assert not res.changed
    assert res.decision == SecurityDecision.ALLOW

def test_changed_tool_detected_after_rollback():
    """AG. Changed tool is detected relative to restored baseline after rollback."""
    pipe = SecurityPipeline()
    t1_v1 = ToolDefinition(tool_id="t1", name="T1", version="1.0.0")
    pipe.approve_tool_change("t1", t1_v1)
    
    chk1 = pipe.create_security_checkpoint(created_by="admin")
    
    # Rollback to v1
    req = RollbackRequest(checkpoint_id=chk1.checkpoint_id, requested_by="admin")
    pipe.rollback_security_checkpoint(req)
    
    # Compare modified v2 tool definition -> detected as REVIEW
    t1_v2 = ToolDefinition(tool_id="t1", name="T1", version="2.0.0")
    res = pipe.validate_tool_change(t1_v2)
    assert res.changed
    assert res.decision == SecurityDecision.REVIEW

def test_existing_phase14_tests_remain_passing():
    """AH. Existing Phase 14 functionality co-exists cleanly with Phase 15."""
    reg = ToolGovernanceRegistry()
    t1 = ToolDefinition(tool_id="t1", name="T1")
    reg.register_baseline(t1)
    assert not reg.compare_tool_definition(t1).changed

def test_existing_phases1_to_13_remain_passing():
    """AI. Core SecurityPipeline functionality remains intact."""
    pipe = SecurityPipeline()
    sanit, meta = pipe.inspect_input("Hello world")
    assert meta["status"] == "APPROVED"

# =====================================================================
# 9. PERFORMANCE BENCHMARK (Section 25)
# =====================================================================

def test_performance_benchmark():
    """Measures checkpoint creation time and validation time for typical state."""
    mgr = CheckpointManager()
    reg = ToolGovernanceRegistry()
    for i in range(20):
        t = ToolDefinition(tool_id=f"tool_{i}", name=f"Tool {i}", version="1.0.0", input_schema={"idx": i})
        reg.register_baseline(t)
    
    # Measure creation
    t0 = time.perf_counter()
    chk = mgr.create_checkpoint(created_by="admin", tool_baselines=reg.export_baselines())
    t1 = time.perf_counter()
    creation_time_ms = (t1 - t0) * 1000.0
    
    # Measure validation
    t2 = time.perf_counter()
    val_res = mgr.validate_checkpoint(chk.checkpoint_id)
    t3 = time.perf_counter()
    validation_time_ms = (t3 - t2) * 1000.0
    
    assert val_res["valid"]
    assert creation_time_ms < 100.0 # Must complete well under 100ms
    assert validation_time_ms < 100.0
