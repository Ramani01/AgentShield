"""
Unit and Integration Tests for Phase 24 Multi-Step Behavioral Detection.
"""

import os
import time
import pytest
import tempfile
from pathlib import Path

from agentshield import AgentShield, ShieldConfig
from agentshield.behavior import (
    BehaviorEventType,
    BehaviorEvent,
    BehaviorSequence,
    BehaviorAssessment,
    BehaviorSequenceCollector,
    BehaviorPattern,
    PatternRegistry,
    BehaviorPatternAnalyzer,
    BehaviorEngine
)
from agentshield.provenance.logger import AuditLogger
from agentshield.capabilities import CapabilityEngine, AgentCapabilityProfile, AgentCapability
from agentshield.communication import CommunicationPolicyEngine, PrincipalType, CommunicationPrincipal
from agentshield.integrity import RuntimeIntegrityEngine, IntegrityState


# =====================================================================
# 1. EVENT TESTS
# =====================================================================

def test_behavior_event_creation_defaults():
    evt = BehaviorEvent(event_type=BehaviorEventType.READ_DOCUMENT)
    assert evt.event_id is not None
    assert evt.timestamp > 0
    assert evt.tenant_id == "default"
    assert evt.agent_id == "default"
    assert evt.event_type == BehaviorEventType.READ_DOCUMENT


def test_behavior_event_normalization_and_hash():
    evt1 = BehaviorEvent(
        tenant_id="tenant_a",
        agent_id="agent_1",
        event_type=BehaviorEventType.READ_MEMORY,
        resource="doc_123"
    )
    evt2 = BehaviorEvent(
        tenant_id="tenant_a",
        agent_id="agent_1",
        event_type=BehaviorEventType.READ_MEMORY,
        resource="doc_123"
    )
    # Different event_ids but identical normalized hash
    assert evt1.compute_event_hash() == evt2.compute_event_hash()


def test_behavior_event_to_dict():
    evt = BehaviorEvent(
        event_type=BehaviorEventType.DATA_EXPORT,
        capability="data:export",
        communication_target="https://api.external.com"
    )
    d = evt.to_dict()
    assert d["event_type"] == BehaviorEventType.DATA_EXPORT
    assert d["capability"] == "data:export"
    assert d["communication_target"] == "https://api.external.com"
    assert "event_hash" in d


# =====================================================================
# 2. COLLECTOR TESTS
# =====================================================================

def test_collector_single_agent_sequence():
    collector = BehaviorSequenceCollector(max_sequence_length=10)
    e1 = BehaviorEvent(tenant_id="t1", agent_id="a1", event_type=BehaviorEventType.READ_DOCUMENT)
    e2 = BehaviorEvent(tenant_id="t1", agent_id="a1", event_type=BehaviorEventType.USE_TOOL)
    collector.record_event(e1)
    collector.record_event(e2)

    seq = collector.get_sequence(tenant_id="t1", agent_id="a1")
    assert len(seq.events) == 2
    assert seq.to_canonical_string() == "READ_DOCUMENT -> USE_TOOL"


def test_collector_agent_and_tenant_isolation():
    collector = BehaviorSequenceCollector(max_sequence_length=10)
    e_t1_a1 = BehaviorEvent(tenant_id="t1", agent_id="a1", event_type=BehaviorEventType.READ_DOCUMENT)
    e_t1_a2 = BehaviorEvent(tenant_id="t1", agent_id="a2", event_type=BehaviorEventType.READ_MEMORY)
    e_t2_a1 = BehaviorEvent(tenant_id="t2", agent_id="a1", event_type=BehaviorEventType.DATA_EXPORT)

    collector.record_event(e_t1_a1)
    collector.record_event(e_t1_a2)
    collector.record_event(e_t2_a1)

    seq_t1_a1 = collector.get_sequence(tenant_id="t1", agent_id="a1")
    seq_t1_a2 = collector.get_sequence(tenant_id="t1", agent_id="a2")
    seq_t2_a1 = collector.get_sequence(tenant_id="t2", agent_id="a1")

    assert len(seq_t1_a1.events) == 1
    assert seq_t1_a1.events[0].event_type == BehaviorEventType.READ_DOCUMENT

    assert len(seq_t1_a2.events) == 1
    assert seq_t1_a2.events[0].event_type == BehaviorEventType.READ_MEMORY

    assert len(seq_t2_a1.events) == 1
    assert seq_t2_a1.events[0].event_type == BehaviorEventType.DATA_EXPORT


def test_collector_bounded_history():
    collector = BehaviorSequenceCollector(max_sequence_length=3)
    for i in range(5):
        collector.record_event(
            BehaviorEvent(
                tenant_id="t1",
                agent_id="a1",
                event_type=BehaviorEventType.USE_TOOL,
                metadata={"index": i}
            )
        )
    seq = collector.get_sequence(tenant_id="t1", agent_id="a1")
    assert len(seq.events) == 3
    # First 2 events should have been dropped
    assert seq.events[0].metadata["index"] == 2
    assert seq.events[2].metadata["index"] == 4


def test_collector_duplicate_event_handling():
    collector = BehaviorSequenceCollector(max_sequence_length=10)
    evt = BehaviorEvent(event_id="fixed_id_123", tenant_id="t1", agent_id="a1", event_type=BehaviorEventType.READ_DOCUMENT)
    collector.record_event(evt)
    collector.record_event(evt)  # Duplicate recording

    seq = collector.get_sequence(tenant_id="t1", agent_id="a1")
    assert len(seq.events) == 1


# =====================================================================
# 3. PATTERN & ANALYZER TESTS
# =====================================================================

def test_exact_pattern_match():
    analyzer = BehaviorPatternAnalyzer()
    # Pattern A: READ_DOCUMENT -> READ_MEMORY -> DATA_EXPORT
    seq = BehaviorSequence(
        tenant_id="t1",
        agent_id="a1",
        events=[
            BehaviorEvent(event_type=BehaviorEventType.READ_DOCUMENT),
            BehaviorEvent(event_type=BehaviorEventType.READ_MEMORY),
            BehaviorEvent(event_type=BehaviorEventType.DATA_EXPORT)
        ]
    )
    assessment = analyzer.analyze_sequence(seq)
    assert assessment.matched is True
    assert assessment.pattern_id == "BEHAVIOR-001"
    assert assessment.risk_level == "HIGH"
    assert assessment.recommended_decision == "REVIEW"


def test_subsequence_with_gaps_match():
    analyzer = BehaviorPatternAnalyzer()
    # Pattern B: READ_DOCUMENT -> USE_TOOL -> EXTERNAL_COMMUNICATION
    seq = BehaviorSequence(
        tenant_id="t1",
        agent_id="a1",
        events=[
            BehaviorEvent(event_type=BehaviorEventType.READ_DOCUMENT),
            BehaviorEvent(event_type=BehaviorEventType.WRITE_MEMORY),  # Gap event 1
            BehaviorEvent(event_type=BehaviorEventType.CREATE_CHECKPOINT),  # Gap event 2
            BehaviorEvent(event_type=BehaviorEventType.USE_TOOL),
            BehaviorEvent(event_type=BehaviorEventType.EXTERNAL_COMMUNICATION)
        ]
    )
    assessment = analyzer.analyze_sequence(seq)
    assert assessment.matched is True
    assert assessment.pattern_id == "BEHAVIOR-002"
    assert assessment.risk_level == "HIGH"


def test_reversed_sequence_rejection():
    analyzer = BehaviorPatternAnalyzer()
    # Reversed of Pattern A: DATA_EXPORT -> READ_MEMORY -> READ_DOCUMENT
    seq = BehaviorSequence(
        tenant_id="t1",
        agent_id="a1",
        events=[
            BehaviorEvent(event_type=BehaviorEventType.DATA_EXPORT),
            BehaviorEvent(event_type=BehaviorEventType.READ_MEMORY),
            BehaviorEvent(event_type=BehaviorEventType.READ_DOCUMENT)
        ]
    )
    assessment = analyzer.analyze_sequence(seq)
    assert assessment.matched is False
    assert assessment.recommended_decision == "ALLOW"


def test_excessive_gap_rejection():
    registry = PatternRegistry(include_defaults=False)
    strict_pattern = BehaviorPattern(
        pattern_id="STRICT-001",
        name="Strict Gap Pattern",
        description="Max gap 1 allowed",
        required_sequence=[BehaviorEventType.READ_DOCUMENT, BehaviorEventType.DATA_EXPORT],
        allow_gaps=True,
        max_gap=1,
        risk_level="HIGH"
    )
    registry.register_pattern(strict_pattern)
    analyzer = BehaviorPatternAnalyzer(registry=registry)

    # 3 intervening events (gap = 3 > max_gap 1)
    seq = BehaviorSequence(
        tenant_id="t1",
        agent_id="a1",
        events=[
            BehaviorEvent(event_type=BehaviorEventType.READ_DOCUMENT),
            BehaviorEvent(event_type=BehaviorEventType.USE_TOOL),
            BehaviorEvent(event_type=BehaviorEventType.WRITE_MEMORY),
            BehaviorEvent(event_type=BehaviorEventType.READ_MEMORY),
            BehaviorEvent(event_type=BehaviorEventType.DATA_EXPORT)
        ]
    )
    assessment = analyzer.analyze_sequence(seq)
    assert assessment.matched is False


# =====================================================================
# 4. ENGINE & DETECTION TESTS
# =====================================================================

def test_engine_no_suspicious_pattern():
    engine = BehaviorEngine()
    a1 = engine.record_event(event_type=BehaviorEventType.READ_DOCUMENT, tenant_id="t1", agent_id="a1")
    assert a1.matched is False
    assert a1.recommended_decision == "ALLOW"

    a2 = engine.record_event(event_type=BehaviorEventType.WRITE_MEMORY, tenant_id="t1", agent_id="a1")
    assert a2.matched is False
    assert a2.recommended_decision == "ALLOW"


def test_engine_critical_pattern_detection():
    engine = BehaviorEngine()
    # Pattern C: MODIFY_CONFIGURATION -> USE_TOOL -> EXTERNAL_COMMUNICATION
    engine.record_event(event_type=BehaviorEventType.MODIFY_CONFIGURATION, tenant_id="t1", agent_id="a1")
    engine.record_event(event_type=BehaviorEventType.USE_TOOL, tenant_id="t1", agent_id="a1")
    assessment = engine.record_event(event_type=BehaviorEventType.EXTERNAL_COMMUNICATION, tenant_id="t1", agent_id="a1")

    assert assessment.matched is True
    assert assessment.pattern_id == "BEHAVIOR-003"
    assert assessment.risk_level == "CRITICAL"
    assert assessment.recommended_decision == "DENY"


# =====================================================================
# 5. SECURITY INVARIANTS & INTEGRATION TESTS
# =====================================================================

def test_invariant_1_and_2_tenant_agent_isolation():
    engine = BehaviorEngine()
    # Tenant 1 Agent 1: READ_DOCUMENT
    engine.record_event(event_type=BehaviorEventType.READ_DOCUMENT, tenant_id="t1", agent_id="a1")
    # Tenant 1 Agent 2: READ_MEMORY
    engine.record_event(event_type=BehaviorEventType.READ_MEMORY, tenant_id="t1", agent_id="a2")
    # Tenant 2 Agent 1: DATA_EXPORT
    assessment = engine.record_event(event_type=BehaviorEventType.DATA_EXPORT, tenant_id="t2", agent_id="a1")

    # None of these isolated single events should trigger Pattern A (READ_DOCUMENT -> READ_MEMORY -> DATA_EXPORT)
    assert assessment.matched is False
    assert engine.get_sequence("t1", "a1").to_canonical_string() == "READ_DOCUMENT"
    assert engine.get_sequence("t1", "a2").to_canonical_string() == "READ_MEMORY"
    assert engine.get_sequence("t2", "a1").to_canonical_string() == "DATA_EXPORT"


def test_invariant_3_detection_does_not_modify_capabilities():
    cap_engine = CapabilityEngine()
    engine = BehaviorEngine(capability_engine=cap_engine)

    # Initial profile state
    profile_before = cap_engine.get_profile(agent_id="a1", tenant_id="t1")

    # Record events with capabilities
    engine.record_event(
        event_type=BehaviorEventType.USE_TOOL,
        tenant_id="t1",
        agent_id="a1",
        capability="admin:delete"
    )

    # Capability profile must be completely untouched (no grants or revokes)
    profile_after = cap_engine.get_profile(agent_id="a1", tenant_id="t1")
    assert profile_after == profile_before


def test_invariant_4_detection_does_not_perform_containment():
    engine = BehaviorEngine()
    # Trigger CRITICAL pattern (BEHAVIOR-003)
    engine.record_event(event_type=BehaviorEventType.MODIFY_CONFIGURATION, tenant_id="t1", agent_id="a1")
    engine.record_event(event_type=BehaviorEventType.USE_TOOL, tenant_id="t1", agent_id="a1")
    assessment = engine.record_event(event_type=BehaviorEventType.EXTERNAL_COMMUNICATION, tenant_id="t1", agent_id="a1")

    assert assessment.matched is True
    assert assessment.recommended_decision == "DENY"
    # Phase 24 returns recommendation only; collector state remains active and intact
    seq = engine.get_sequence("t1", "a1")
    assert len(seq.events) == 3


def test_invariant_5_no_trust_elevation():
    engine = BehaviorEngine()
    assessment = engine.record_event(
        event_type=BehaviorEventType.READ_DOCUMENT,
        tenant_id="t1",
        agent_id="a1",
        trust_level="UNTRUSTED",
        metadata={"attempt_elevation": True}
    )
    event_recorded = engine.get_sequence("t1", "a1").events[0]
    assert event_recorded.trust_level == "UNTRUSTED"


def test_invariant_6_determinism():
    engine1 = BehaviorEngine()
    engine2 = BehaviorEngine()

    events = [
        BehaviorEventType.READ_DOCUMENT,
        BehaviorEventType.READ_MEMORY,
        BehaviorEventType.DATA_EXPORT
    ]

    res1 = None
    res2 = None
    for et in events:
        res1 = engine1.record_event(event_type=et, tenant_id="t1", agent_id="a1")
        res2 = engine2.record_event(event_type=et, tenant_id="t1", agent_id="a1")

    assert res1.matched == res2.matched
    assert res1.pattern_id == res2.pattern_id
    assert res1.risk_level == res2.risk_level
    assert res1.confidence == res2.confidence
    assert res1.recommended_decision == res2.recommended_decision


def test_audit_logger_integration(tmp_path):
    log_path = tmp_path / "behavior_audit.jsonl"
    logger = AuditLogger(log_file_path=str(log_path))
    engine = BehaviorEngine(audit_logger=logger)

    engine.record_event(event_type=BehaviorEventType.READ_DOCUMENT, tenant_id="t1", agent_id="a1")
    engine.record_event(event_type=BehaviorEventType.READ_MEMORY, tenant_id="t1", agent_id="a1")
    engine.record_event(event_type=BehaviorEventType.DATA_EXPORT, tenant_id="t1", agent_id="a1")

    # Verify audit log integrity
    integrity = logger.verify_log_integrity()
    assert integrity["valid"] is True
    assert integrity["entries_checked"] >= 3


def test_agentshield_facade_integration():
    shield = AgentShield()
    assert hasattr(shield, "behavior_engine")
    assert isinstance(shield.behavior_engine, BehaviorEngine)

    assessment = shield.behavior_engine.record_event(
        event_type=BehaviorEventType.READ_DOCUMENT,
        tenant_id="facade_tenant",
        agent_id="facade_agent"
    )
    assert assessment.matched is False
    assert assessment.recommended_decision == "ALLOW"
