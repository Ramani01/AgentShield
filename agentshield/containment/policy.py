"""
Phase 25: Containment Policy Engine and Rule Definitions.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from agentshield.behavior.models import BehaviorEventType
from agentshield.containment.models import ContainmentState, IsolationLevel


@dataclass
class ContainmentPolicy:
    """Configurable security policy determining containment triggers and action restrictions."""
    policy_id: str = "default_containment_policy"
    name: str = "Standard Security Containment Policy"
    auto_contain_on_critical_behavior: bool = True
    auto_contain_on_high_behavior: bool = True
    auto_contain_on_invalid_runtime: bool = True
    restricted_actions_by_level: Dict[str, List[str]] = field(default_factory=lambda: {
        IsolationLevel.NONE: [],
        IsolationLevel.MONITOR: [],
        IsolationLevel.RESTRICTED: [
            BehaviorEventType.MODIFY_CONFIGURATION,
            BehaviorEventType.DATA_EXPORT,
        ],
        IsolationLevel.FULL: [
            BehaviorEventType.MODIFY_CONFIGURATION,
            BehaviorEventType.DATA_EXPORT,
            BehaviorEventType.EXTERNAL_COMMUNICATION,
            BehaviorEventType.USE_TOOL,
            BehaviorEventType.EXECUTE_ACTION,
            BehaviorEventType.WRITE_MEMORY,
        ]
    })
    allowed_recovery_actions: List[str] = field(default_factory=lambda: [
        BehaviorEventType.CREATE_CHECKPOINT,
        BehaviorEventType.ROLLBACK_CHECKPOINT,
        BehaviorEventType.READ_DOCUMENT,
    ])


class ContainmentPolicyEngine:
    """Evaluates containment triggers and action restriction rules."""

    def __init__(self, policy: Optional[ContainmentPolicy] = None):
        self.policy = policy or ContainmentPolicy()

    def evaluate_behavior_assessment(
        self, assessment: Any
    ) -> Tuple[bool, str, str, str]:
        """
        Evaluates a Phase 24 BehaviorAssessment against containment policy.
        Returns (should_contain, target_state, target_isolation_level, reason).
        """
        if not assessment or not getattr(assessment, "matched", False):
            return False, ContainmentState.NORMAL, IsolationLevel.NONE, "No behavioral pattern matched."

        risk_level = getattr(assessment, "risk_level", "LOW")
        pattern_id = getattr(assessment, "pattern_id", "UNKNOWN")
        pattern_name = getattr(assessment, "pattern_name", "Unknown Pattern")

        if risk_level == "CRITICAL" and self.policy.auto_contain_on_critical_behavior:
            return (
                True,
                ContainmentState.CONTAINED,
                IsolationLevel.FULL,
                f"CRITICAL risk pattern '{pattern_id}' ({pattern_name}) triggered full containment."
            )

        if risk_level == "HIGH" and self.policy.auto_contain_on_high_behavior:
            return (
                True,
                ContainmentState.CONTAINED,
                IsolationLevel.RESTRICTED,
                f"HIGH risk pattern '{pattern_id}' ({pattern_name}) triggered restricted containment."
            )

        if getattr(assessment, "recommended_decision", "ALLOW") in ("REVIEW", "DENY"):
            return (
                True,
                ContainmentState.SUSPECTED,
                IsolationLevel.MONITOR,
                f"Behavior recommendation '{assessment.recommended_decision}' triggered monitoring."
            )

        return False, ContainmentState.NORMAL, IsolationLevel.NONE, "Behavior within acceptable bounds."

    def evaluate_runtime_integrity(
        self, integrity_state: str
    ) -> Tuple[bool, str, str, str]:
        """
        Evaluates Phase 23 runtime integrity state against containment policy.
        """
        if integrity_state in ("INVALID", "DRIFTED") and self.policy.auto_contain_on_invalid_runtime:
            return (
                True,
                ContainmentState.CONTAINED,
                IsolationLevel.FULL,
                f"Runtime environment integrity state '{integrity_state}' triggered emergency containment."
            )
        return False, ContainmentState.NORMAL, IsolationLevel.NONE, "Runtime integrity valid."

    def is_action_restricted(self, isolation_level: str, action_type: str) -> bool:
        """
        Checks whether a specific action_type is restricted under the given isolation_level.
        """
        if isolation_level in (IsolationLevel.NONE, IsolationLevel.MONITOR):
            return False

        restricted_list = self.policy.restricted_actions_by_level.get(isolation_level, [])
        return action_type in restricted_list
