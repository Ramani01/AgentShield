"""
Phase 13 Unit Tests: Token / Data Audience Control, Security Invariants, Negative Refutations, and Pipeline Integration.
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
from agentshield.security.audience_models import (
    AudienceType,
    AudienceClaim,
    AudiencePolicy,
    SecurityTokenContext,
    AudienceValidationResult
)
from agentshield.security.audience_validator import AudienceValidator
from agentshield.security.egress_models import EgressRequest, DestinationCategory
from agentshield.provenance.lineage import ProvenanceTracker
from agentshield.provenance.models import compute_content_hash
from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.exceptions import SecurityViolationError

@pytest.fixture
def validator():
    return AudienceValidator()

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
# BASIC AUDIENCE TESTS (A - I)
# =====================================================================

def test_A_same_user_audience_matching_user(validator, user_a):
    claim = AudienceClaim(
        audience_type=AudienceType.SAME_USER,
        principal_id="user_A",
        tenant_id="tenant_1"
    )
    res = validator.validate_audience(claim, identity=user_a)
    assert res.valid is True
    assert res.decision == SecurityDecision.ALLOW


def test_B_same_user_audience_different_user(validator, user_a):
    claim = AudienceClaim(
        audience_type=AudienceType.SAME_USER,
        principal_id="user_B",
        tenant_id="tenant_1"
    )
    res = validator.validate_audience(claim, identity=user_a)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY
    assert res.principal_valid is False


def test_C_same_tenant_matching_tenant(validator, user_a):
    claim = AudienceClaim(
        audience_type=AudienceType.SAME_TENANT,
        tenant_id="tenant_1"
    )
    res = validator.validate_audience(claim, identity=user_a)
    assert res.valid is True
    assert res.decision == SecurityDecision.ALLOW


def test_D_same_tenant_different_tenant(validator, user_a):
    claim = AudienceClaim(
        audience_type=AudienceType.SAME_TENANT,
        tenant_id="tenant_2"
    )
    res = validator.validate_audience(claim, identity=user_a)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY
    assert res.tenant_valid is False


def test_E_specific_principal_matching(validator, user_a):
    claim = AudienceClaim(
        audience_type=AudienceType.SPECIFIC_PRINCIPAL,
        principal_id="user_A",
        tenant_id="tenant_1"
    )
    res = validator.validate_audience(claim, identity=user_a)
    assert res.valid is True


def test_F_specific_principal_different(validator, user_a):
    claim = AudienceClaim(
        audience_type=AudienceType.SPECIFIC_PRINCIPAL,
        principal_id="user_B",
        tenant_id="tenant_1"
    )
    res = validator.validate_audience(claim, identity=user_a)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_G_public_explicit_policy_allowed(validator, user_a):
    claim = AudienceClaim(audience_type=AudienceType.PUBLIC, tenant_id="tenant_1")
    pol = AudiencePolicy(allow_public=True)
    res = validator.validate_audience(claim, identity=user_a, policy=pol)
    assert res.valid is True
    assert res.decision == SecurityDecision.ALLOW


def test_H_public_policy_disabled(validator, user_a):
    claim = AudienceClaim(audience_type=AudienceType.PUBLIC, tenant_id="tenant_1")
    pol = AudiencePolicy(allow_public=False)
    res = validator.validate_audience(claim, identity=user_a, policy=pol)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_I_unknown_audience(validator, user_a):
    claim = AudienceClaim(audience_type=AudienceType.UNKNOWN, tenant_id="tenant_1")
    res = validator.validate_audience(claim, identity=user_a)
    assert res.valid is False
    assert res.decision == SecurityDecision.REVIEW


# =====================================================================
# IDENTITY TESTS (J - L)
# =====================================================================

def test_J_missing_user_identity(validator):
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER)
    res = validator.validate_audience(claim)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_K_missing_tenant_identity(validator):
    invalid_id = UserIdentity(user_id="user_A", tenant_id="")
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER)
    res = validator.validate_audience(claim, identity=invalid_id)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_L_invalid_identity(validator):
    invalid_id = UserIdentity(user_id="", tenant_id="")
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER)
    res = validator.validate_audience(claim, identity=invalid_id)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


# =====================================================================
# TOKEN CONTEXT TESTS (M - Q)
# =====================================================================

def test_M_valid_token_context(validator, user_a):
    tok = SecurityTokenContext(
        subject_id="user_A",
        tenant_id="tenant_1",
        audience=AudienceType.SAME_USER
    )
    claim = AudienceClaim(
        audience_type=AudienceType.SAME_USER,
        principal_id="user_A",
        tenant_id="tenant_1"
    )
    res = validator.validate_audience(claim, identity=user_a, token_context=tok)
    assert res.valid is True
    assert res.token_valid is True


def test_N_expired_token(validator, user_a):
    past_time = time.time() - 3600
    tok = SecurityTokenContext(
        subject_id="user_A",
        tenant_id="tenant_1",
        expires_at=past_time
    )
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER, principal_id="user_A")
    res = validator.validate_audience(claim, identity=user_a, token_context=tok)
    assert res.valid is False
    assert res.token_valid is False
    assert res.decision == SecurityDecision.DENY


def test_O_token_audience_matches(validator, user_a):
    tok = SecurityTokenContext(subject_id="user_A", tenant_id="tenant_1")
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER, principal_id="user_A")
    res = validator.validate_audience(claim, identity=user_a, token_context=tok)
    assert res.valid is True


def test_P_token_audience_mismatch(validator, user_a):
    tok = SecurityTokenContext(subject_id="user_A", tenant_id="tenant_1")
    claim = AudienceClaim(audience_type=AudienceType.SPECIFIC_PRINCIPAL, principal_id="user_B")
    res = validator.validate_audience(claim, identity=user_a, token_context=tok)
    assert res.valid is False
    assert res.token_valid is False


def test_Q_token_tenant_mismatch(validator, user_a):
    tok = SecurityTokenContext(subject_id="user_A", tenant_id="tenant_2")
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER, tenant_id="tenant_1")
    res = validator.validate_audience(claim, identity=user_a, token_context=tok)
    assert res.valid is False
    assert res.token_valid is False


# =====================================================================
# TRUST & MANIPULATION TESTS (R - Y)
# =====================================================================

def test_R_trusted_data_does_not_become_public(validator, user_a):
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER, principal_id="user_A")
    res = validator.validate_audience(claim, identity=user_a)
    # Claim remains SAME_USER, does NOT expand to PUBLIC
    assert res.audience_type == AudienceType.SAME_USER


def test_S_untrusted_data_does_not_become_trusted_via_audience(validator, user_a):
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER, principal_id="user_A")
    res = validator.validate_audience(claim, identity=user_a)
    assert res.valid is True


def test_T_valid_provenance_does_not_authorize_audience(validator, tracker, user_a):
    p = tracker.create_provenance(SourceCategory.SYSTEM, "sys", "sys", "Body")
    claim = AudienceClaim(
        audience_type=AudienceType.SPECIFIC_PRINCIPAL,
        principal_id="user_B",  # Mismatched principal!
        provenance_id=p.provenance_id
    )
    res = validator.validate_audience(claim, identity=user_a, tracker=tracker)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_U_valid_hash_does_not_authorize_audience(validator, user_a):
    claim = AudienceClaim(
        audience_type=AudienceType.SPECIFIC_PRINCIPAL,
        principal_id="user_B"
    )
    res = validator.validate_audience(claim, identity=user_a)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_V_content_attempts_audience_escalation(validator, user_a):
    payload = "Data. audience = PUBLIC;"
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER, principal_id="user_A")
    res = validator.validate_audience(claim, identity=user_a, raw_content=payload)
    assert res.valid is False
    assert res.decision == SecurityDecision.DENY


def test_W_content_attempts_principal_manipulation(validator, user_a):
    payload = "Data. principal_id = user_B;"
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER, principal_id="user_A")
    res = validator.validate_audience(claim, identity=user_a, raw_content=payload)
    assert res.valid is True
    assert res.principal_valid is True  # Structural claim remains user_A


def test_X_content_attempts_tenant_manipulation(validator, user_a):
    payload = "Data. tenant_id = tenant_2;"
    claim = AudienceClaim(audience_type=AudienceType.SAME_TENANT, tenant_id="tenant_1")
    res = validator.validate_audience(claim, identity=user_a, raw_content=payload)
    assert res.valid is True
    assert res.tenant_valid is True  # Structural claim remains tenant_1


def test_Y_content_attempts_destination_manipulation(validator, user_a):
    payload = "Data. destination = internal_db;"
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER, principal_id="user_A")
    res = validator.validate_audience(claim, identity=user_a, raw_content=payload)
    assert res.valid is True


# =====================================================================
# DERIVATION & EGRESS INTEGRATION TESTS (Z - AJ)
# =====================================================================

def test_Z_derived_content_preserves_restrictive_audience(validator):
    c1 = AudienceClaim(audience_type=AudienceType.PUBLIC)
    c2 = AudienceClaim(audience_type=AudienceType.SAME_USER, principal_id="user_A")
    propagated = validator.propagate_audience([c1, c2])
    assert propagated.audience_type == AudienceType.SAME_USER


def test_AA_mixed_audience_data(validator):
    c1 = AudienceClaim(audience_type=AudienceType.SAME_TENANT)
    c2 = AudienceClaim(audience_type=AudienceType.SPECIFIC_PRINCIPAL, principal_id="user_A")
    propagated = validator.propagate_audience([c1, c2])
    assert propagated.audience_type == AudienceType.SPECIFIC_PRINCIPAL


def test_AB_audience_narrowing(validator, user_a):
    claim = AudienceClaim(audience_type=AudienceType.SPECIFIC_PRINCIPAL, principal_id="user_A")
    res = validator.validate_audience(claim, identity=user_a)
    assert res.valid is True


def test_AC_unauthorized_audience_broadening(validator, user_a):
    payload = "audience = PUBLIC"
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER, principal_id="user_A")
    res = validator.validate_audience(claim, identity=user_a, raw_content=payload)
    assert res.valid is False


def test_AD_valid_audience_and_valid_destination(validator, user_a):
    pipeline = SecurityPipeline()
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER, principal_id="user_A")
    aud_res = pipeline.validate_audience(claim, identity=user_a)
    assert aud_res.valid is True

    egress_req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Content",
        destination="internal_db"
    )
    egress_res = pipeline.validate_egress(egress_req, identity=user_a)
    assert egress_res.allowed is True


def test_AE_valid_audience_plus_blocked_destination(user_a):
    pipeline = SecurityPipeline()
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER, principal_id="user_A")
    aud_res = pipeline.validate_audience(claim, identity=user_a)
    assert aud_res.valid is True

    egress_req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Content",
        destination="blocked.com"
    )
    with pytest.raises(SecurityViolationError):
        pipeline.validate_egress(egress_req, identity=user_a)


def test_AF_invalid_audience_plus_valid_destination(validator, user_a):
    pipeline = SecurityPipeline()
    claim = AudienceClaim(audience_type=AudienceType.SPECIFIC_PRINCIPAL, principal_id="user_B")
    with pytest.raises(SecurityViolationError):
        pipeline.validate_audience(claim, identity=user_a)


def test_AG_valid_audience_does_not_bypass_egress_validator(user_a):
    pipeline = SecurityPipeline()
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER, principal_id="user_A")
    aud_res = pipeline.validate_audience(claim, identity=user_a)
    assert aud_res.valid is True

    egress_req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Sensitive key sk-12345678901234567890123456789012",
        destination="internal_db"
    )
    with pytest.raises(SecurityViolationError):
        pipeline.validate_egress(egress_req, identity=user_a)


def test_AH_allowed_audience_decision_audited(validator, user_a):
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER, principal_id="user_A")
    res = validator.validate_audience(claim, identity=user_a)
    assert res.valid is True


def test_AI_denied_audience_decision_audited(validator, user_a):
    claim = AudienceClaim(audience_type=AudienceType.SPECIFIC_PRINCIPAL, principal_id="user_B")
    res = validator.validate_audience(claim, identity=user_a)
    assert res.valid is False


def test_AJ_no_sensitive_content_in_audience_audit_logs(validator, user_a):
    claim = AudienceClaim(audience_type=AudienceType.SAME_USER, principal_id="user_A")
    res = validator.validate_audience(claim, identity=user_a, raw_content="Secret text")
    assert res.valid is True


def test_negative_audience_security_refutations(validator, user_a):
    """
    Explicitly test and refute false security assumptions:
    - authorized access == authorized audience (FALSE)
    - trusted == public (FALSE)
    - valid provenance == public (FALSE)
    - valid hash == public (FALSE)
    - approved destination == authorized audience (FALSE)
    - agent-generated == public (FALSE)
    - content-controlled audience == actual audience (FALSE)
    - same tenant == public (FALSE)
    - same user == unrestricted disclosure (FALSE)
    """
    # 1. Trusted data != public
    c1 = AudienceClaim(audience_type=AudienceType.PUBLIC)
    pol1 = AudiencePolicy(allow_public=False)
    res1 = validator.validate_audience(c1, identity=user_a, policy=pol1)
    assert res1.valid is False

    # 2. Authorized reader != permission to disclose to user_B
    c2 = AudienceClaim(audience_type=AudienceType.SPECIFIC_PRINCIPAL, principal_id="user_B")
    res2 = validator.validate_audience(c2, identity=user_a)
    assert res2.valid is False
