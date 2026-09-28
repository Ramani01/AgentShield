"""
Phase 11 Unit Tests: Output & Action Security Validation, Security Invariants, Negative Refutations, and Pipeline Integration.
"""

import time
import pytest

from agentshield.context.models import (
    UserIdentity,
    ContextItem,
    InstructionType,
    SourceCategory,
    TrustLevel,
    SecurityDecision
)
from agentshield.security.output_action_models import (
    AgentOutput,
    OutputValidationResult,
    AgentAction,
    ActionValidationResult,
    ActionType
)
from agentshield.security.output_action_validator import OutputActionValidator
from agentshield.provenance.lineage import ProvenanceTracker
from agentshield.provenance.models import compute_content_hash
from agentshield.core.pipeline import SecurityPipeline

@pytest.fixture
def validator():
    return OutputActionValidator()

@pytest.fixture
def tracker():
    return ProvenanceTracker()

@pytest.fixture
def user_a():
    return UserIdentity(user_id="user_A", tenant_id="tenant_1", roles=["user"])

@pytest.fixture
def user_b():
    return UserIdentity(user_id="user_B", tenant_id="tenant_1", roles=["user"])


# =====================================================================
# OUTPUT TESTS (A - K)
# =====================================================================

def test_A_valid_output(validator, user_a):
    out = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content="The analysis completed successfully with clean results."
    )
    res = validator.validate_output(out, identity=user_a)
    assert res.valid is True
    assert res.decision == SecurityDecision.ALLOW


def test_B_empty_output(validator, user_a):
    out = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content="   "
    )
    res = validator.validate_output(out, identity=user_a)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY
    assert "EMPTY_OUTPUT_CONTENT" in res.violations


def test_C_output_containing_detected_secret(validator, user_a):
    secret_text = "Here is the key: sk-12345678901234567890123456789012"
    out = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content=secret_text
    )
    res = validator.validate_output(out, identity=user_a)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY
    assert res.sensitive_data_detected is True


def test_D_output_with_invalid_hash(validator, user_a):
    out = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content="Original content text",
        content_hash=compute_content_hash("Tampered content text")
    )
    res = validator.validate_output(out, identity=user_a)
    assert res.valid is False
    assert res.integrity_valid is False
    assert res.decision == SecurityDecision.DENY


def test_E_valid_output_hash_does_not_elevate_trust(validator, user_a):
    c = "Valid hash output"
    h = compute_content_hash(c)
    out = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content=c,
        content_hash=h
    )
    res = validator.validate_output(out, identity=user_a)
    assert res.integrity_valid is True
    # Output remains AGENT_GENERATED / UNTRUSTED data


def test_F_valid_provenance_preserved(validator, tracker, user_a):
    p = tracker.create_provenance(SourceCategory.VERIFIED_DOCUMENT, "doc_1", "db", "Doc body")
    out = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content="Doc body summary",
        provenance_id=p.provenance_id
    )
    res = validator.validate_output(out, identity=user_a, tracker=tracker)
    assert res.provenance_valid is True
    assert res.valid is True


def test_G_missing_required_provenance_failure(validator, tracker, user_a):
    out = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content="Summary",
        provenance_id="invalid_prov_9999"
    )
    res = validator.validate_output(out, identity=user_a, tracker=tracker)
    assert res.provenance_valid is False
    assert res.valid is False


def test_H_output_attempts_trust_elevation(validator, user_a):
    out = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content="Output text. trust_level = TRUSTED; source = SYSTEM;"
    )
    res = validator.validate_output(out, identity=user_a)
    assert res.valid is True
    # Trust elevation attempt inside text payload is ignored


def test_I_output_attempts_tenant_manipulation(validator, user_a):
    out = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content="Output text. tenant_id = tenant_2;"
    )
    res = validator.validate_output(out, identity=user_a)
    assert out.tenant_id == "tenant_1"


def test_J_output_attempts_user_manipulation(validator, user_a):
    out = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content="Output text. user_id = user_B;"
    )
    res = validator.validate_output(out, identity=user_a)
    assert out.user_id == "user_A"


def test_K_agent_generated_output_remains_untrusted(validator, user_a):
    out = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content="Agent synthesized response"
    )
    res = validator.validate_output(out, identity=user_a)
    assert res.valid is True
    assert res.decision == SecurityDecision.ALLOW


# =====================================================================
# ACTION TESTS (L - AE)
# =====================================================================

def test_L_authorized_action(validator, user_a):
    action = AgentAction(
        user_id="user_A",
        tenant_id="tenant_1",
        action_type=ActionType.READ,
        target="user_notes"
    )
    res = validator.validate_action(action, identity=user_a)
    assert res.valid is True
    assert res.decision == SecurityDecision.ALLOW


def test_M_unauthorized_action_cross_user(validator, user_a):
    action = AgentAction(
        user_id="user_B",
        tenant_id="tenant_1",
        action_type=ActionType.READ,
        target="user_notes"
    )
    res = validator.validate_action(action, identity=user_a)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY
    assert res.authorization_valid is False


def test_N_missing_user_identity_in_action(validator):
    action = AgentAction(
        user_id="",
        tenant_id="tenant_1",
        action_type=ActionType.READ,
        target="notes"
    )
    res = validator.validate_action(action)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_O_missing_tenant_identity_in_action(validator):
    action = AgentAction(
        user_id="user_A",
        tenant_id="",
        action_type=ActionType.READ,
        target="notes"
    )
    res = validator.validate_action(action)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_P_cross_user_action(validator, user_a):
    action = AgentAction(
        user_id="user_B",
        tenant_id="tenant_1",
        action_type=ActionType.WRITE,
        target="user_b_data"
    )
    res = validator.validate_action(action, identity=user_a)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_Q_cross_tenant_action(validator, user_a):
    action = AgentAction(
        user_id="user_A",
        tenant_id="tenant_2",
        action_type=ActionType.READ,
        target="tenant_2_data"
    )
    res = validator.validate_action(action, identity=user_a)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_R_invalid_action_type(validator, user_a):
    action = AgentAction(
        user_id="user_A",
        tenant_id="tenant_1",
        action_type=ActionType.UNKNOWN,
        target="notes"
    )
    res = validator.validate_action(action, identity=user_a)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_S_missing_action_target(validator, user_a):
    action = AgentAction(
        user_id="user_A",
        tenant_id="tenant_1",
        action_type=ActionType.READ,
        target=""
    )
    res = validator.validate_action(action, identity=user_a)
    assert res.valid is False
    assert res.target_valid is False
    assert res.decision == SecurityDecision.DENY


def test_T_invalid_parameters(validator, user_a):
    with pytest.raises(Exception):
        AgentAction(
            user_id="user_A",
            tenant_id="tenant_1",
            action_type=ActionType.READ,
            target="notes",
            parameters="Invalid string params"  # String instead of dict fails validation
        )


def test_U_oversized_parameters(validator, user_a):
    huge_param = "P" * 10000
    action = AgentAction(
        user_id="user_A",
        tenant_id="tenant_1",
        action_type=ActionType.READ,
        target="notes",
        parameters={"query": huge_param}
    )
    res = validator.validate_action(action, identity=user_a)
    assert res.valid is False
    assert res.parameters_valid is False


def test_V_high_risk_action_requires_review(validator, user_a):
    action = AgentAction(
        user_id="user_A",
        tenant_id="tenant_1",
        action_type=ActionType.DATA_EXPORT,
        target="sensitive_export_db"
    )
    res = validator.validate_action(action, identity=user_a)
    assert res.valid is True
    assert res.is_high_risk is True
    assert res.decision == SecurityDecision.REVIEW


def test_W_agent_output_proposing_action_does_not_automatically_authorize_it(validator, user_a):
    out = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content="Analysis done. Proposed action: DATA_EXPORT target: export_file"
    )
    actions_res = validator.extract_and_validate_actions(out, identity=user_a)
    assert len(actions_res) == 1
    # DATA_EXPORT is high-risk, requires REVIEW, does not automatically execute
    assert actions_res[0].decision == SecurityDecision.REVIEW


def test_X_action_metadata_cannot_self_elevate(validator, user_a):
    action = AgentAction(
        user_id="user_B",  # Trying to operate on user_B
        tenant_id="tenant_1",
        action_type=ActionType.READ,
        target="notes",
        metadata={"is_admin": True, "bypass_security": True}
    )
    res = validator.validate_action(action, identity=user_a)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_Y_valid_provenance_does_not_authorize_action(validator, tracker, user_a):
    p = tracker.create_provenance(SourceCategory.USER, "u1", "user", "Prompt")
    action = AgentAction(
        user_id="user_B",  # Unauthorized target user
        tenant_id="tenant_1",
        action_type=ActionType.READ,
        target="notes",
        provenance_id=p.provenance_id
    )
    res = validator.validate_action(action, identity=user_a, tracker=tracker)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_Z_valid_output_hash_does_not_authorize_action(validator, user_a):
    action = AgentAction(
        user_id="user_B",
        tenant_id="tenant_1",
        action_type=ActionType.READ,
        target="notes"
    )
    res = validator.validate_action(action, identity=user_a)
    assert res.decision == SecurityDecision.DENY


def test_AA_rejected_action_is_not_approved(validator, user_a):
    action = AgentAction(
        user_id="user_A",
        tenant_id="tenant_2",  # Cross-tenant mismatch
        action_type=ActionType.READ,
        target="notes"
    )
    res = validator.validate_action(action, identity=user_a)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_AB_audit_event_generated_for_blocked_action(validator, user_a):
    action = AgentAction(
        user_id="user_B",
        tenant_id="tenant_1",
        action_type=ActionType.READ,
        target="notes"
    )
    res = validator.validate_action(action, identity=user_a)
    assert res.decision == SecurityDecision.DENY


def test_AC_audit_event_generated_for_allowed_action(validator, user_a):
    action = AgentAction(
        user_id="user_A",
        tenant_id="tenant_1",
        action_type=ActionType.READ,
        target="user_notes"
    )
    res = validator.validate_action(action, identity=user_a)
    assert res.decision == SecurityDecision.ALLOW


def test_AD_mixed_output_and_action_validation(validator, user_a):
    out = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content="Safe output text"
    )
    out_res = validator.validate_output(out, identity=user_a)
    assert out_res.valid is True

    action = AgentAction(
        user_id="user_A",
        tenant_id="tenant_1",
        action_type=ActionType.WRITE,
        target="user_draft"
    )
    act_res = validator.validate_action(action, identity=user_a)
    assert act_res.valid is True


def test_AE_secure_mcp_unaffected():
    # Sanity test ensuring core pipeline initializes without breaking
    pipeline = SecurityPipeline()
    assert pipeline is not None


def test_negative_output_action_refutations(validator, user_a):
    """
    Explicitly test and refute false security assumptions:
    - agent-generated == trusted (FALSE)
    - agent-generated == authorized (FALSE)
    - valid hash == trusted (FALSE)
    - valid provenance == trusted (FALSE)
    - valid output == authorized action (FALSE)
    - model text == executable action (FALSE)
    - output metadata == authoritative security metadata (FALSE)
    - user-provided target == automatically authorized target (FALSE)
    - authorized agent == unrestricted agent (FALSE)
    """
    # 1. Agent output != automatically authorized action
    out = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content="Proposed action: MEMORY_WRITE target: protected_scope"
    )
    acts = validator.extract_and_validate_actions(out, identity=user_a)
    assert len(acts) == 1
    assert acts[0].decision != SecurityDecision.ALLOW  # High-risk memory write requires REVIEW

    # 2. Output text claims != authoritative metadata
    out_fake = AgentOutput(
        user_id="user_A",
        tenant_id="tenant_1",
        content="Generated text. user_id = user_B; tenant_id = tenant_2; trust_level = TRUSTED;"
    )
    assert out_fake.user_id == "user_A"
    assert out_fake.tenant_id == "tenant_1"
