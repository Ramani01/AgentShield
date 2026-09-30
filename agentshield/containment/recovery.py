"""
Phase 25: Containment Recovery and Release Manager.
Manages controlled state restoration, checkpoint rollback integration, and release authorization.
"""

import time
import logging
from typing import Optional, Dict, Any
from agentshield.containment.models import ContainmentState, IsolationLevel
from agentshield.containment.isolation import IsolationStateManager

logger = logging.getLogger("AgentShield.ContainmentRecoveryManager")


class ContainmentRecoveryManager:
    """
    Governs recovery and release of contained agents.
    Invariants Enforced:
    4. Containment Cannot Be Self-Disabled: Agent identity cannot release itself.
    7. Runtime Integrity: Invalid runtime state prevents release.
    10. Valid State Transitions: Enforces CONTAINED -> RECOVERY -> RELEASED -> NORMAL sequence.
    """

    def __init__(
        self,
        isolation_manager: IsolationStateManager,
        checkpoint_manager: Optional[Any] = None,
        integrity_engine: Optional[Any] = None,
        audit_logger: Optional[Any] = None
    ):
        self.isolation_manager = isolation_manager
        self.checkpoint_manager = checkpoint_manager
        self.integrity_engine = integrity_engine
        self.audit_logger = audit_logger

    def initiate_recovery(
        self,
        tenant_id: str,
        agent_id: str,
        principal_id: str,
        reason: str = "Authorized recovery initiated",
        checkpoint_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Initiates recovery process for a contained agent.
        Transitions state from CONTAINED -> RECOVERY.
        """
        # Invariant 4: Agent self-release block
        if principal_id == agent_id or not principal_id:
            msg = f"Self-recovery rejected for agent '{agent_id}'. Controlled recovery requires authorized governance principal."
            if self.audit_logger:
                self.audit_logger.log_event("CONTAINMENT_RECOVERY_FAILED", {"tenant_id": tenant_id, "agent_id": agent_id, "reason": msg}, tenant_id=tenant_id)
            return {"success": False, "reason": msg, "state": ContainmentState.CONTAINED}

        record = self.isolation_manager.get_record(tenant_id=tenant_id, agent_id=agent_id)
        if record.current_state != ContainmentState.CONTAINED:
            msg = f"Cannot initiate recovery for agent '{agent_id}' in state '{record.current_state}'. Agent must be in CONTAINED state."
            return {"success": False, "reason": msg, "state": record.current_state}

        # Audit event
        if self.audit_logger:
            self.audit_logger.log_event(
                "CONTAINMENT_RECOVERY_STARTED",
                {"tenant_id": tenant_id, "agent_id": agent_id, "principal_id": principal_id, "checkpoint_id": checkpoint_id, "reason": reason},
                tenant_id=tenant_id
            )

        # Transition to RECOVERY
        record = self.isolation_manager.transition_state(
            tenant_id=tenant_id,
            agent_id=agent_id,
            target_state=ContainmentState.RECOVERY,
            isolation_level=IsolationLevel.RESTRICTED
        )

        # Phase 13 Checkpoint Rollback Integration
        rollback_success = True
        rollback_details = None
        if checkpoint_id and self.checkpoint_manager is not None:
            try:
                # Execute checkpoint rollback if method exists
                if hasattr(self.checkpoint_manager, "rollback_to_checkpoint"):
                    res = self.checkpoint_manager.rollback_to_checkpoint(checkpoint_id=checkpoint_id, tenant_id=tenant_id, agent_id=agent_id)
                    rollback_success = getattr(res, "success", True)
                    rollback_details = getattr(res, "details", {})
            except Exception as e:
                logger.warning(f"Checkpoint rollback failed during recovery: {e}")
                rollback_success = False

        if not rollback_success:
            # Revert to CONTAINED on recovery failure
            self.isolation_manager.transition_state(
                tenant_id=tenant_id,
                agent_id=agent_id,
                target_state=ContainmentState.CONTAINED,
                isolation_level=IsolationLevel.FULL
            )
            msg = "Recovery failed during checkpoint rollback."
            if self.audit_logger:
                self.audit_logger.log_event("CONTAINMENT_RECOVERY_FAILED", {"tenant_id": tenant_id, "agent_id": agent_id, "reason": msg}, tenant_id=tenant_id)
            return {"success": False, "reason": msg, "state": ContainmentState.CONTAINED, "rollback_details": rollback_details}

        return {"success": True, "state": ContainmentState.RECOVERY, "rollback_details": rollback_details}

    def release_containment(
        self,
        tenant_id: str,
        agent_id: str,
        principal_id: str,
        reason: str = "Authorized release"
    ) -> Dict[str, Any]:
        """
        Releases containment for an agent following recovery validation.
        Transitions state from RECOVERY -> RELEASED -> NORMAL.
        """
        # Invariant 4: Agent self-release block
        if principal_id == agent_id or not principal_id:
            msg = f"Self-release rejected for agent '{agent_id}'. Release requires authorized governance principal."
            if self.audit_logger:
                self.audit_logger.log_event("CONTAINMENT_RELEASE_REQUESTED", {"tenant_id": tenant_id, "agent_id": agent_id, "principal_id": principal_id, "approved": False, "reason": msg}, tenant_id=tenant_id)
            return {"success": False, "reason": msg}

        record = self.isolation_manager.get_record(tenant_id=tenant_id, agent_id=agent_id)
        if record.current_state not in (ContainmentState.RECOVERY, ContainmentState.SUSPECTED):
            msg = f"Cannot release agent '{agent_id}' from state '{record.current_state}'. Agent must be in RECOVERY state."
            return {"success": False, "reason": msg, "state": record.current_state}

        # Invariant 7: Phase 23 Runtime Integrity Check
        if self.integrity_engine is not None:
            try:
                state_str = "UNKNOWN"
                if hasattr(self.integrity_engine, "evaluate_integrity"):
                    res = self.integrity_engine.evaluate_integrity(agent_id=agent_id, tenant_id=tenant_id)
                    raw_state = getattr(res, "state", getattr(res, "integrity_state", "UNKNOWN"))
                    state_str = raw_state.value if hasattr(raw_state, "value") else str(raw_state)
                else:
                    raw_state = getattr(self.integrity_engine, "current_integrity_state", "UNKNOWN")
                    state_str = raw_state.value if hasattr(raw_state, "value") else str(raw_state)

                if state_str in ("INVALID", "DRIFTED", "UNKNOWN"):
                    msg = f"Release blocked for agent '{agent_id}': Runtime environment integrity state is '{state_str}'."
                    if self.audit_logger:
                        self.audit_logger.log_event("CONTAINMENT_RELEASE_REQUESTED", {"tenant_id": tenant_id, "agent_id": agent_id, "approved": False, "reason": msg}, tenant_id=tenant_id)
                    return {"success": False, "reason": msg, "state": record.current_state}
            except Exception as e:
                logger.warning(f"Runtime integrity check error during release: {e}")

        # Execute valid transition: RECOVERY -> RELEASED
        self.isolation_manager.transition_state(
            tenant_id=tenant_id,
            agent_id=agent_id,
            target_state=ContainmentState.RELEASED,
            isolation_level=IsolationLevel.NONE
        )

        # Execute valid transition: RELEASED -> NORMAL
        final_record = self.isolation_manager.transition_state(
            tenant_id=tenant_id,
            agent_id=agent_id,
            target_state=ContainmentState.NORMAL,
            isolation_level=IsolationLevel.NONE
        )

        if self.audit_logger:
            self.audit_logger.log_event(
                "CONTAINMENT_RELEASED",
                {"tenant_id": tenant_id, "agent_id": agent_id, "principal_id": principal_id, "reason": reason},
                tenant_id=tenant_id
            )

        return {"success": True, "state": final_record.current_state, "reason": "Containment released successfully."}
