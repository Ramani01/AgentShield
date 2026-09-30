"""
Phase 25: Containment Manager.
Main facade orchestrator for Agent Isolation & Emergency Containment.
"""

import time
import logging
from typing import Optional, Dict, Any, List
from agentshield.containment.models import (
    ContainmentState,
    IsolationLevel,
    ContainmentRequest,
    ContainmentRecord,
    GateDecision
)
from agentshield.containment.isolation import IsolationStateManager
from agentshield.containment.policy import ContainmentPolicyEngine, ContainmentPolicy
from agentshield.containment.action_gate import ContainmentActionGate
from agentshield.containment.recovery import ContainmentRecoveryManager

logger = logging.getLogger("AgentShield.ContainmentManager")


class ContainmentManager:
    """
    Main Phase 25 Containment Manager.

    Security Invariants Enforced:
    1. Tenant Isolation: Tenant A cannot alter Tenant B's agent state.
    2. Agent Isolation: Agent A cannot alter Agent B's containment state.
    3. No Capability Elevation: Containment can only restrict, never grant capabilities.
    4. Containment Cannot Be Self-Disabled: Contained agent cannot release itself.
    5. Containment Policy Protection: Contained agent cannot modify configuration or containment policy.
    6. Authorization Composition: Final decision = Existing Auth AND Containment Permission.
    7. Runtime Integrity: Invalid runtime integrity prevents release.
    8. Determinism: Identical request + state = identical outcome.
    9. Idempotency: Repeated emergency containment requests are safe and idempotent.
    10. Valid State Transitions: Enforces valid state machine transitions.
    11. Audit Integrity: Emits tamper-evident log records for state changes and blocks.
    12. Previous Controls Authoritative: All previous Phase 1-24 security controls remain authoritative.
    """

    def __init__(
        self,
        policy: Optional[ContainmentPolicy] = None,
        audit_logger: Optional[Any] = None,
        capability_engine: Optional[Any] = None,
        comm_engine: Optional[Any] = None,
        integrity_engine: Optional[Any] = None,
        checkpoint_manager: Optional[Any] = None
    ):
        self.audit_logger = audit_logger
        self.capability_engine = capability_engine
        self.comm_engine = comm_engine
        self.integrity_engine = integrity_engine
        self.checkpoint_manager = checkpoint_manager

        self.isolation_manager = IsolationStateManager()
        self.policy_engine = ContainmentPolicyEngine(policy=policy)
        self.action_gate = ContainmentActionGate(
            isolation_manager=self.isolation_manager,
            policy_engine=self.policy_engine,
            capability_engine=self.capability_engine,
            comm_engine=self.comm_engine,
            audit_logger=self.audit_logger
        )
        self.recovery_manager = ContainmentRecoveryManager(
            isolation_manager=self.isolation_manager,
            checkpoint_manager=self.checkpoint_manager,
            integrity_engine=self.integrity_engine,
            audit_logger=self.audit_logger
        )

    def request_emergency_containment(
        self,
        tenant_id: str = "default",
        agent_id: str = "default",
        reason: str = "Emergency Containment Requested",
        source_control: str = "EMERGENCY_GATE",
        severity: str = "HIGH",
        isolation_level: str = IsolationLevel.FULL,
        principal_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ContainmentRecord:
        """
        Requests immediate emergency containment for an agent.
        Deterministic, idempotent, and tenant/agent isolated.
        """
        request = ContainmentRequest(
            tenant_id=tenant_id,
            agent_id=agent_id,
            principal_id=principal_id,
            reason=reason,
            source_control=source_control,
            severity=severity,
            isolation_level=isolation_level,
            metadata=metadata or {}
        )

        current_record = self.isolation_manager.get_record(tenant_id=tenant_id, agent_id=agent_id)

        # Audit logger - request received
        if self.audit_logger:
            self.audit_logger.log_event(
                "CONTAINMENT_REQUESTED",
                request.to_dict(),
                tenant_id=tenant_id
            )

        # Idempotency check: If already CONTAINED, update and return without corrupting history
        if current_record.current_state == ContainmentState.CONTAINED:
            if self.audit_logger:
                self.audit_logger.log_event(
                    "CONTAINMENT_ALREADY_ACTIVE",
                    {"tenant_id": tenant_id, "agent_id": agent_id, "state": ContainmentState.CONTAINED},
                    tenant_id=tenant_id
                )
            return self.isolation_manager.transition_state(
                tenant_id=tenant_id,
                agent_id=agent_id,
                target_state=ContainmentState.CONTAINED,
                isolation_level=isolation_level,
                request=request
            )

        # Execute transition: NORMAL or SUSPECTED -> CONTAINED
        updated_record = self.isolation_manager.transition_state(
            tenant_id=tenant_id,
            agent_id=agent_id,
            target_state=ContainmentState.CONTAINED,
            isolation_level=isolation_level,
            request=request
        )

        if self.audit_logger:
            self.audit_logger.log_event(
                "CONTAINMENT_TRIGGERED",
                updated_record.to_dict(),
                tenant_id=tenant_id
            )
            self.audit_logger.log_event(
                "CONTAINMENT_STATE_CHANGED",
                {"tenant_id": tenant_id, "agent_id": agent_id, "new_state": ContainmentState.CONTAINED, "isolation_level": isolation_level},
                tenant_id=tenant_id
            )

        return updated_record

    def evaluate_behavior_and_contain(
        self,
        tenant_id: str,
        agent_id: str,
        behavior_assessment: Any
    ) -> ContainmentRecord:
        """
        Evaluates a Phase 24 BehaviorAssessment and triggers containment if policy dictates.
        """
        should_contain, target_state, target_level, reason = self.policy_engine.evaluate_behavior_assessment(
            assessment=behavior_assessment
        )

        if should_contain:
            return self.request_emergency_containment(
                tenant_id=tenant_id,
                agent_id=agent_id,
                reason=reason,
                source_control="PHASE_24_BEHAVIORAL_DETECTOR",
                severity=getattr(behavior_assessment, "risk_level", "HIGH"),
                isolation_level=target_level,
                metadata={"pattern_id": getattr(behavior_assessment, "pattern_id", None)}
            )

        return self.isolation_manager.get_record(tenant_id=tenant_id, agent_id=agent_id)

    def evaluate_runtime_integrity_and_contain(
        self,
        tenant_id: str,
        agent_id: str,
        integrity_state: str
    ) -> ContainmentRecord:
        """
        Evaluates Phase 23 runtime environment integrity state and triggers emergency containment if invalid.
        """
        should_contain, target_state, target_level, reason = self.policy_engine.evaluate_runtime_integrity(
            integrity_state=integrity_state
        )

        if should_contain:
            return self.request_emergency_containment(
                tenant_id=tenant_id,
                agent_id=agent_id,
                reason=reason,
                source_control="PHASE_23_RUNTIME_INTEGRITY",
                severity="CRITICAL",
                isolation_level=target_level
            )

        return self.isolation_manager.get_record(tenant_id=tenant_id, agent_id=agent_id)

    def evaluate_action_gate(
        self,
        tenant_id: str,
        agent_id: str,
        action_type: str,
        capability: Optional[str] = None,
        communication_target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> GateDecision:
        """Evaluates an action request through the containment action gate."""
        return self.action_gate.evaluate_action(
            tenant_id=tenant_id,
            agent_id=agent_id,
            action_type=action_type,
            capability=capability,
            communication_target=communication_target,
            metadata=metadata
        )

    def initiate_recovery(
        self,
        tenant_id: str,
        agent_id: str,
        principal_id: str,
        reason: str = "Authorized recovery",
        checkpoint_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Initiates authorized recovery for a contained agent."""
        return self.recovery_manager.initiate_recovery(
            tenant_id=tenant_id,
            agent_id=agent_id,
            principal_id=principal_id,
            reason=reason,
            checkpoint_id=checkpoint_id
        )

    def release_containment(
        self,
        tenant_id: str,
        agent_id: str,
        principal_id: str,
        reason: str = "Authorized release"
    ) -> Dict[str, Any]:
        """Releases containment for a recovered agent."""
        return self.recovery_manager.release_containment(
            tenant_id=tenant_id,
            agent_id=agent_id,
            principal_id=principal_id,
            reason=reason
        )

    def get_containment_status(self, tenant_id: str = "default", agent_id: str = "default") -> Dict[str, Any]:
        """Retrieves containment state status dictionary for (tenant_id, agent_id)."""
        record = self.isolation_manager.get_record(tenant_id=tenant_id, agent_id=agent_id)
        return record.to_dict()
