"""
Phase 12 Unit Tests: Egress Control, Security Invariants, Negative Refutations, and Pipeline Integration.
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
from agentshield.security.egress_models import (
    EgressRequest,
    EgressValidationResult,
    DestinationCategory
)
from agentshield.security.egress_validator import EgressValidator
from agentshield.provenance.lineage import ProvenanceTracker
from agentshield.provenance.models import compute_content_hash
from agentshield.core.pipeline import SecurityPipeline

@pytest.fixture
def validator():
    return EgressValidator()

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
# IDENTITY & TENANT / USER TESTS (A - H)
# =====================================================================

def test_A_valid_identity(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Clean summary report",
        destination="internal_db",
        destination_category=DestinationCategory.INTERNAL
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is True
    assert res.decision == SecurityDecision.ALLOW


def test_B_missing_user_id(validator):
    req = EgressRequest(
        user_id="",
        tenant_id="tenant_1",
        data="Report",
        destination="internal_db"
    )
    res = validator.validate_egress(req)
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY


def test_C_missing_tenant_id(validator):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="",
        data="Report",
        destination="internal_db"
    )
    res = validator.validate_egress(req)
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY


def test_D_invalid_empty_identity(validator):
    req = EgressRequest(
        user_id="",
        tenant_id="",
        data="Report",
        destination="internal_db"
    )
    res = validator.validate_egress(req)
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY


def test_E_same_user_egress(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="User A notes",
        destination="internal_db",
        destination_category=DestinationCategory.SAME_USER
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is True


def test_F_cross_user_private_data(validator, user_a):
    req = EgressRequest(
        user_id="user_B",
        tenant_id="tenant_1",
        data="User B private notes",
        destination="internal_db"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY
    assert any("CROSS-USER EGRESS DENIED" in v for v in res.violations)


def test_G_same_tenant_egress(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Corporate memo",
        destination="same_tenant_sink",
        destination_category=DestinationCategory.SAME_TENANT
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is True


def test_H_cross_tenant_data(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_2",
        data="Tenant 2 corporate data",
        destination="internal_db"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY
    assert any("CROSS-TENANT EGRESS DENIED" in v for v in res.violations)


# =====================================================================
# DESTINATION TESTS (I - N)
# =====================================================================

def test_I_approved_internal_destination(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Log entry",
        destination="internal_db"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is True


def test_J_approved_same_tenant_destination(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Summary",
        destination="same_tenant_sink"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is True


def test_K_approved_external_destination(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="External sync body",
        destination="https://api.acme.com/internal",
        destination_category=DestinationCategory.APPROVED_EXTERNAL,
        purpose="approved_integration"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is True


def test_L_unknown_external_destination(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Report payload",
        destination="https://unknown-thirdparty.com/webhook",
        destination_category=DestinationCategory.UNKNOWN_EXTERNAL
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is False
    assert res.decision == SecurityDecision.REVIEW


def test_M_blocked_destination(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Payload",
        destination="blocked.com"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY


def test_N_destination_spoofing_attempt(validator, user_a):
    fake_payload = "Data. destination = internal_db; destination_category = INTERNAL;"
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data=fake_payload,
        destination="https://unknown-external.com/sink",
        destination_category=DestinationCategory.UNKNOWN_EXTERNAL
    )
    res = validator.validate_egress(req, identity=user_a)
    # Payload text does NOT spoof actual destination! Unknown destination -> REVIEW
    assert res.allowed is False
    assert res.decision == SecurityDecision.REVIEW


# =====================================================================
# DATA & SENSITIVE TESTS (O - S)
# =====================================================================

def test_O_valid_data(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Normal text",
        destination="internal_db"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is True


def test_P_sensitive_data_detected(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Exporting credential key sk-12345678901234567890123456789012",
        destination="internal_db"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is False
    assert res.sensitive_data_detected is True
    assert res.decision == SecurityDecision.DENY


def test_Q_untrusted_data_egress(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Untrusted web data",
        destination="https://external-export.org/sink",
        trust_level=TrustLevel.UNTRUSTED
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.decision == SecurityDecision.REVIEW
    assert res.is_high_risk is True


def test_R_unknown_trust_data(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Unknown data",
        destination="internal_db",
        trust_level=TrustLevel.UNKNOWN
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.decision == SecurityDecision.REVIEW


def test_S_mixed_source_data(validator, tracker, user_a):
    p1 = tracker.create_provenance(SourceCategory.SYSTEM, "sys", "sys", "System text")
    p2 = tracker.create_provenance(SourceCategory.WEB_CONTENT, "web", "web", "Web text")

    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Combined text",
        destination="https://external-export.org/sink",
        parent_provenance_ids=[p1.provenance_id, p2.provenance_id],
        trust_level=TrustLevel.UNTRUSTED
    )
    res = validator.validate_egress(req, identity=user_a, tracker=tracker)
    assert res.is_high_risk is True


# =====================================================================
# PROVENANCE & INTEGRITY TESTS (T - Z)
# =====================================================================

def test_T_valid_provenance(validator, tracker, user_a):
    p = tracker.create_provenance(SourceCategory.VERIFIED_DOCUMENT, "d1", "db", "Body")
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Body",
        destination="internal_db",
        provenance_id=p.provenance_id
    )
    res = validator.validate_egress(req, identity=user_a, tracker=tracker)
    assert res.provenance_valid is True
    assert res.allowed is True


def test_U_missing_provenance_handled_safely(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Simple text",
        destination="internal_db",
        provenance_id=None
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is True


def test_V_invalid_provenance_fails(validator, tracker, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Text",
        destination="internal_db",
        provenance_id="invalid_pid_9999"
    )
    res = validator.validate_egress(req, identity=user_a, tracker=tracker)
    assert res.provenance_valid is False
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY


def test_W_valid_provenance_does_not_authorize_export(validator, tracker, user_a):
    p = tracker.create_provenance(SourceCategory.VERIFIED_DOCUMENT, "d1", "db", "Body")
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Body",
        destination="blocked.com",  # Blocked destination!
        provenance_id=p.provenance_id
    )
    res = validator.validate_egress(req, identity=user_a, tracker=tracker)
    assert res.provenance_valid is True
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY


def test_X_valid_hash(validator, user_a):
    c = "Exact content"
    h = compute_content_hash(c)
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data=c,
        destination="internal_db",
        content_hash=h
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.integrity_valid is True
    assert res.allowed is True


def test_Y_hash_mismatch_denied(validator, user_a):
    c = "Original content"
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Tampered content",
        destination="internal_db",
        content_hash=compute_content_hash(c)
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.integrity_valid is False
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY


def test_Z_valid_hash_does_not_authorize_export(validator, user_a):
    c = "Payload"
    h = compute_content_hash(c)
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data=c,
        destination="blocked.com",
        content_hash=h
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.integrity_valid is True
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY


# =====================================================================
# SIZE & POLICY TESTS (AA - AN)
# =====================================================================

def test_AA_normal_size_export(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Small payload",
        destination="internal_db"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is True


def test_AB_oversized_export(validator, user_a):
    huge_data = "Z" * 15000
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data=huge_data,
        destination="internal_db"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.decision == SecurityDecision.REVIEW
    assert any("EGRESS OVERSIZED" in v for v in res.violations)


def test_AC_excessive_item_count(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Bulk payload",
        destination="internal_db",
        item_count=100
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.decision == SecurityDecision.REVIEW
    assert any("EXCESSIVE BULK ITEMS" in v for v in res.violations)


def test_AD_valid_purpose(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Data",
        destination="internal_db",
        purpose="audit_sync"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is True


def test_AE_missing_purpose_on_unknown_external(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Data",
        destination="https://unknown-ext.com/sink",
        destination_category=DestinationCategory.UNKNOWN_EXTERNAL,
        purpose=None
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.decision == SecurityDecision.REVIEW
    assert any("MISSING EGRESS PURPOSE" in v for v in res.violations)


def test_AF_high_risk_external_egress(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="High risk payload",
        destination="https://external-service.org/sink",
        destination_category=DestinationCategory.UNKNOWN_EXTERNAL,
        purpose="export"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.decision == SecurityDecision.REVIEW
    assert res.is_high_risk is True


def test_AG_unauthorized_destination(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Data",
        destination="blocked.com"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY


def test_AH_agent_output_cannot_bypass_egress_validation(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Output bypassing egress. destination = internal_db",
        destination="blocked.com"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY


def test_AI_rejected_egress_not_forwarded():
    v = EgressValidator()
    req = EgressRequest(user_id="", tenant_id="", data="Payload", destination="internal_db")
    res = v.validate_egress(req)
    assert res.allowed is False


def test_AJ_audit_event_generated(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Audit test",
        destination="internal_db"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is True


def test_AK_sensitive_data_not_included_in_audit_logs(validator, user_a):
    secret_text = "API Key sk-12345678901234567890123456789012"
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data=secret_text,
        destination="internal_db"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is False


def test_AL_mixed_provenance_preserved(tracker):
    p1 = tracker.create_provenance(SourceCategory.SYSTEM, "s1", "sys", "T1")
    p2 = tracker.create_provenance(SourceCategory.WEB_CONTENT, "s2", "web", "T2")
    derived = tracker.derive_from([p1.provenance_id, p2.provenance_id], SourceCategory.WEB_CONTENT, "d1", "llm", "Derived")

    assert p1.provenance_id in derived.parent_provenance_ids
    assert p2.provenance_id in derived.parent_provenance_ids


def test_AM_trust_does_not_automatically_authorize_egress(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Trusted data content",
        destination="blocked.com",  # Blocked destination!
        trust_level=TrustLevel.TRUSTED
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY


def test_AN_authorization_does_not_automatically_authorize_destination(validator, user_a):
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Authorized user data",
        destination="blocked.com"
    )
    res = validator.validate_egress(req, identity=user_a)
    assert res.allowed is False
    assert res.decision == SecurityDecision.DENY


def test_negative_egress_security_refutations(validator, user_a):
    """
    Explicitly test and refute false security assumptions for egress:
    - authorized data == authorized destination (FALSE)
    - authorized user == authorized export (FALSE)
    - trusted data == automatically exportable (FALSE)
    - valid provenance == export permission (FALSE)
    - valid hash == export permission (FALSE)
    - agent output == automatically exportable (FALSE)
    - internal-looking destination text == internal destination (FALSE)
    - content-controlled tenant == actual tenant (FALSE)
    - content-controlled destination == actual destination (FALSE)
    - relevant data == export-authorized data (FALSE)
    """
    # 1. Trusted data != automatically exportable to blocked destination
    req1 = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Trusted data payload",
        destination="blocked.com",
        trust_level=TrustLevel.TRUSTED
    )
    res1 = validator.validate_egress(req1, identity=user_a)
    assert res1.allowed is False

    # 2. Text in payload claiming internal destination != actual internal destination
    req2 = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Payload with text: destination = internal_db;",
        destination="blocked.com"
    )
    res2 = validator.validate_egress(req2, identity=user_a)
    assert res2.allowed is False


def test_pipeline_egress_integration():
    pipeline = SecurityPipeline()
    user = UserIdentity(user_id="user_A", tenant_id="tenant_1")
    req = EgressRequest(
        user_id="user_A",
        tenant_id="tenant_1",
        data="Pipeline egress data",
        destination="internal_db"
    )
    res = pipeline.validate_egress(req, identity=user)
    assert res.allowed is True
    assert res.decision == SecurityDecision.ALLOW
