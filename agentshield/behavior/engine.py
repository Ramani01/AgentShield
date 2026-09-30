"""
Phase 24: Multi-Step Behavioral Detection Engine.
Main orchestrator for behavioral sequence collection, pattern analysis, and integration.
"""

import time
import logging
from typing import Optional, Dict, Any, List
from agentshield.behavior.models import (
    BehaviorEvent,
    BehaviorSequence,
    BehaviorAssessment,
    BehaviorEventType
)
from agentshield.behavior.collector import BehaviorSequenceCollector
from agentshield.behavior.patterns import PatternRegistry, BehaviorPattern
from agentshield.behavior.analyzer import BehaviorPatternAnalyzer

logger = logging.getLogger("AgentShield.BehaviorEngine")


class BehaviorEngine:
    """
    Main Phase 24 Multi-Step Behavioral Detection Engine.

    Detection Engine Security Invariants:
    1. Tenant Isolation: Events from different tenants never mix.
    2. Agent Isolation: Events from different agents never mix.
    3. Detection != Authorization: Cannot grant/revoke capabilities (Phase 21 remains authoritative).
    4. Detection != Containment: Cannot perform runtime isolation/kill (Phase 24 is detection only).
    5. No Trust Elevation: Cannot transform UNTRUSTED/UNKNOWN -> TRUSTED.
    6. Determinism: Same sequence + same configuration = same assessment.
    7. Bounded State: History buffer is bounded per agent.
    8. Previous Controls Authoritative: Cannot bypass any previous Phase 1-23 control.
    """

    def __init__(
        self,
        collector: Optional[BehaviorSequenceCollector] = None,
        analyzer: Optional[BehaviorPatternAnalyzer] = None,
        pattern_registry: Optional[PatternRegistry] = None,
        audit_logger: Optional[Any] = None,
        capability_engine: Optional[Any] = None,
        comm_engine: Optional[Any] = None,
        integrity_engine: Optional[Any] = None,
        max_sequence_length: int = 100
    ):
        self.collector = collector or BehaviorSequenceCollector(max_sequence_length=max_sequence_length)
        self.pattern_registry = pattern_registry or PatternRegistry(include_defaults=True)
        self.analyzer = analyzer or BehaviorPatternAnalyzer(registry=self.pattern_registry)

        self.audit_logger = audit_logger
        self.capability_engine = capability_engine
        self.comm_engine = comm_engine
        self.integrity_engine = integrity_engine

    def record_event(
        self,
        event_type: str,
        tenant_id: str = "default",
        agent_id: str = "default",
        principal_id: Optional[str] = None,
        resource: Optional[str] = None,
        capability: Optional[str] = None,
        communication_target: Optional[str] = None,
        trust_level: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        event: Optional[BehaviorEvent] = None
    ) -> BehaviorAssessment:
        """
        Records a behavioral event and evaluates the updated sequence.
        Returns the resulting BehaviorAssessment.
        """
        if event is None:
            event = BehaviorEvent(
                tenant_id=tenant_id or "default",
                agent_id=agent_id or "default",
                principal_id=principal_id,
                event_type=event_type or BehaviorEventType.UNKNOWN,
                resource=resource,
                capability=capability,
                communication_target=communication_target,
                trust_level=trust_level,
                metadata=metadata or {}
            )

        # Enforce Invariant 5: No Trust Elevation
        # If trust_level is UNTRUSTED or UNKNOWN, it cannot be elevated to TRUSTED
        if event.trust_level in ("UNTRUSTED", "UNKNOWN", None) and metadata and metadata.get("attempt_elevation"):
            event.trust_level = "UNTRUSTED"

        # Phase 23 Runtime Integrity Integration Context (Enforce Invariant 5 & 8)
        if self.integrity_engine is not None:
            try:
                # Retrieve current integrity state without mutating it
                latest_snapshot = getattr(self.integrity_engine, "latest_snapshot", None)
                if latest_snapshot:
                    event.runtime_integrity_state = getattr(latest_snapshot, "integrity_state", "UNKNOWN")
            except Exception as e:
                logger.debug(f"Failed to fetch runtime integrity context: {e}")

        # Phase 21 Capability Context Integration (Enforce Invariant 3)
        if self.capability_engine is not None and capability and not event.capability:
            event.capability = capability

        # Phase 22 Communication Policy Integration (Enforce Invariant 8)
        if self.comm_engine is not None and communication_target and not event.communication_target:
            event.communication_target = communication_target

        # Record event into isolated bounded collector (Enforces Invariants 1, 2 & 7)
        recorded_event = self.collector.record_event(event)

        # Audit log event recording
        if self.audit_logger is not None:
            try:
                self.audit_logger.log_event(
                    event_type="BEHAVIOR_EVENT_RECORDED",
                    tenant_id=recorded_event.tenant_id,
                    details=recorded_event.to_dict()
                )
            except Exception as e:
                logger.warning(f"Audit logger error during event record: {e}")

        # Evaluate complete sequence
        return self.evaluate_sequence(tenant_id=recorded_event.tenant_id, agent_id=recorded_event.agent_id)

    def evaluate_sequence(self, tenant_id: str = "default", agent_id: str = "default") -> BehaviorAssessment:
        """
        Evaluates the behavioral sequence of a specific agent/tenant.
        Returns deterministic BehaviorAssessment.
        """
        sequence = self.collector.get_sequence(tenant_id=tenant_id, agent_id=agent_id)
        assessment = self.analyzer.analyze_sequence(sequence)

        # Attach Phase 23 runtime integrity snapshot context if available
        if self.integrity_engine is not None:
            try:
                latest_snapshot = getattr(self.integrity_engine, "latest_snapshot", None)
                if latest_snapshot:
                    assessment.runtime_integrity_state = str(getattr(latest_snapshot, "integrity_state", "UNKNOWN"))
                    assessment.runtime_snapshot_reference = getattr(latest_snapshot, "snapshot_id", None)
                baseline = getattr(self.integrity_engine, "baseline", None)
                if baseline:
                    assessment.runtime_baseline_reference = getattr(baseline, "baseline_id", None)
            except Exception as e:
                logger.debug(f"Failed to attach integrity details to assessment: {e}")

        # Audit logging of pattern detections and recommendations
        if self.audit_logger is not None and assessment.matched:
            try:
                self.audit_logger.log_event(
                    event_type="BEHAVIOR_SEQUENCE_MATCH",
                    tenant_id=tenant_id,
                    details={
                        "agent_id": agent_id,
                        "pattern_id": assessment.pattern_id,
                        "pattern_name": assessment.pattern_name,
                        "risk_level": assessment.risk_level,
                        "recommended_decision": assessment.recommended_decision,
                        "confidence": assessment.confidence
                    }
                )
                self.audit_logger.log_event(
                    event_type="BEHAVIOR_PATTERN_DETECTED",
                    tenant_id=tenant_id,
                    details=assessment.to_dict()
                )
                if assessment.recommended_decision in ("REVIEW", "DENY"):
                    self.audit_logger.log_event(
                        event_type="BEHAVIOR_REVIEW_REQUIRED",
                        tenant_id=tenant_id,
                        details={
                            "agent_id": agent_id,
                            "pattern_id": assessment.pattern_id,
                            "recommended_decision": assessment.recommended_decision
                        }
                    )
            except Exception as e:
                logger.warning(f"Audit logger error during sequence evaluation: {e}")

        return assessment

    def get_sequence(self, tenant_id: str = "default", agent_id: str = "default") -> BehaviorSequence:
        """Retrieves raw collected sequence for tenant and agent."""
        return self.collector.get_sequence(tenant_id=tenant_id, agent_id=agent_id)

    def clear_sequence(self, tenant_id: str = "default", agent_id: str = "default") -> None:
        """Clears sequence history for tenant and agent."""
        self.collector.clear_sequence(tenant_id=tenant_id, agent_id=agent_id)

    def register_pattern(self, pattern: BehaviorPattern) -> None:
        """Registers a custom behavior detection pattern."""
        self.pattern_registry.register_pattern(pattern)
