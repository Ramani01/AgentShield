"""
Phase 25: Containment Action Gate.
Evaluates agent action requests against active containment states and restrictions.
"""

import logging
from typing import Optional, Dict, Any
from agentshield.behavior.models import BehaviorEventType
from agentshield.containment.models import ContainmentState, IsolationLevel, GateDecision
from agentshield.containment.isolation import IsolationStateManager
from agentshield.containment.policy import ContainmentPolicyEngine

logger = logging.getLogger("AgentShield.ContainmentActionGate")


class ContainmentActionGate:
    """
    Action Gate enforcing containment restrictions on requested agent operations.

    Invariants Enforced:
    3. No Capability Elevation: Gate never grants capabilities; it only restricts authority.
    5. Containment Policy Protection: Contained agent cannot modify configuration or containment policy.
    6. Authorization Composition: Final decision = Existing Authorization AND Containment Permission.
    12. Previous Controls Authoritative: Existing Phase 1-24 controls remain authoritative.
    """

    def __init__(
        self,
        isolation_manager: IsolationStateManager,
        policy_engine: ContainmentPolicyEngine,
        capability_engine: Optional[Any] = None,
        comm_engine: Optional[Any] = None,
        audit_logger: Optional[Any] = None
    ):
        self.isolation_manager = isolation_manager
        self.policy_engine = policy_engine
        self.capability_engine = capability_engine
        self.comm_engine = comm_engine
        self.audit_logger = audit_logger

    def evaluate_action(
        self,
        tenant_id: str,
        agent_id: str,
        action_type: str,
        capability: Optional[str] = None,
        communication_target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> GateDecision:
        """
        Evaluates a requested action against current containment state and policy restrictions.
        """
        record = self.isolation_manager.get_record(tenant_id=tenant_id, agent_id=agent_id)
        current_state = record.current_state
        isolation_level = record.isolation_level

        # Case 1: NORMAL state or NONE isolation
        if current_state == ContainmentState.NORMAL or isolation_level == IsolationLevel.NONE:
            return GateDecision(
                allowed=True,
                decision="ALLOW",
                reason="Agent operates under normal security conditions.",
                isolation_level=isolation_level,
                containment_state=current_state
            )

        # Case 2: SUSPECTED state or MONITOR isolation
        if current_state == ContainmentState.SUSPECTED or isolation_level == IsolationLevel.MONITOR:
            if self.audit_logger:
                self.audit_logger.log_event(
                    "CONTAINMENT_ACTION_ALLOWED",
                    {"tenant_id": tenant_id, "agent_id": agent_id, "action_type": action_type, "isolation_level": isolation_level, "mode": "MONITOR"},
                    tenant_id=tenant_id
                )
            return GateDecision(
                allowed=True,
                decision="ALLOW",
                reason="Action permitted under MONITOR isolation mode.",
                isolation_level=isolation_level,
                containment_state=current_state
            )

        # Invariant 5: Contained agent cannot modify configuration or policy
        if action_type == BehaviorEventType.MODIFY_CONFIGURATION:
            reason = f"Action '{action_type}' blocked: Contained agents cannot modify configuration or security policy."
            if self.audit_logger:
                self.audit_logger.log_event(
                    "CONTAINMENT_ACTION_BLOCKED",
                    {"tenant_id": tenant_id, "agent_id": agent_id, "action_type": action_type, "isolation_level": isolation_level, "reason": reason},
                    tenant_id=tenant_id
                )
            return GateDecision(
                allowed=False,
                decision="DENY",
                reason=reason,
                isolation_level=isolation_level,
                containment_state=current_state,
                restricted_action=action_type
            )

        # Case 3: CONTAINED state (RESTRICTED or FULL)
        if self.policy_engine.is_action_restricted(isolation_level=isolation_level, action_type=action_type):
            reason = f"Action '{action_type}' blocked by containment policy under '{isolation_level}' isolation."
            if self.audit_logger:
                self.audit_logger.log_event(
                    "CONTAINMENT_ACTION_BLOCKED",
                    {"tenant_id": tenant_id, "agent_id": agent_id, "action_type": action_type, "isolation_level": isolation_level, "reason": reason},
                    tenant_id=tenant_id
                )
            return GateDecision(
                allowed=False,
                decision="DENY",
                reason=reason,
                isolation_level=isolation_level,
                containment_state=current_state,
                restricted_action=action_type
            )

        # Log allowed non-restricted action under containment
        if self.audit_logger:
            self.audit_logger.log_event(
                "CONTAINMENT_ACTION_ALLOWED",
                {"tenant_id": tenant_id, "agent_id": agent_id, "action_type": action_type, "isolation_level": isolation_level},
                tenant_id=tenant_id
            )

        return GateDecision(
            allowed=True,
            decision="ALLOW",
            reason=f"Action '{action_type}' permitted under '{isolation_level}' isolation.",
            isolation_level=isolation_level,
            containment_state=current_state
        )
