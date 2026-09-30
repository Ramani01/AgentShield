"""
Phase 25: Agent Isolation & Emergency Containment Models.
"""

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional


class ContainmentState:
    """Explicit containment state machine states."""
    NORMAL = "NORMAL"
    SUSPECTED = "SUSPECTED"
    CONTAINED = "CONTAINED"
    RECOVERY = "RECOVERY"
    RELEASED = "RELEASED"

    @classmethod
    def all_states(cls) -> List[str]:
        return [cls.NORMAL, cls.SUSPECTED, cls.CONTAINED, cls.RECOVERY, cls.RELEASED]


class IsolationLevel:
    """Framework-level isolation levels."""
    NONE = "NONE"
    MONITOR = "MONITOR"
    RESTRICTED = "RESTRICTED"
    FULL = "FULL"

    @classmethod
    def all_levels(cls) -> List[str]:
        return [cls.NONE, cls.MONITOR, cls.RESTRICTED, cls.FULL]


class InvalidStateTransitionError(ValueError):
    """Raised when an invalid containment state transition is attempted."""
    pass


# Deterministic state transition map
ALLOWED_STATE_TRANSITIONS: Dict[str, List[str]] = {
    ContainmentState.NORMAL: [ContainmentState.SUSPECTED, ContainmentState.CONTAINED],
    ContainmentState.SUSPECTED: [ContainmentState.CONTAINED, ContainmentState.NORMAL],
    ContainmentState.CONTAINED: [ContainmentState.RECOVERY, ContainmentState.CONTAINED],  # Idempotent re-containment allowed
    ContainmentState.RECOVERY: [ContainmentState.RELEASED, ContainmentState.CONTAINED],   # Recovery failure returns to CONTAINED
    ContainmentState.RELEASED: [ContainmentState.NORMAL],
}


def validate_state_transition(from_state: str, to_state: str) -> bool:
    """
    Validates if a state transition from from_state to to_state is allowed.
    Raises InvalidStateTransitionError if invalid.
    """
    if from_state == to_state and from_state == ContainmentState.CONTAINED:
        return True  # Idempotent containment

    allowed_next = ALLOWED_STATE_TRANSITIONS.get(from_state, [])
    if to_state not in allowed_next:
        raise InvalidStateTransitionError(
            f"Invalid containment state transition from '{from_state}' to '{to_state}'."
        )
    return True


@dataclass
class ContainmentRequest:
    """Request payload to initiate or modify containment state."""
    containment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default"
    agent_id: str = "default"
    principal_id: Optional[str] = None
    reason: str = "Security Trigger"
    source_control: str = "CONTAINMENT_GATE"
    severity: str = "HIGH"
    behavior_pattern_id: Optional[str] = None
    runtime_integrity_state: Optional[str] = None
    isolation_level: str = IsolationLevel.FULL
    requested_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.requested_at:
            self.requested_at = time.time()
        if not self.containment_id:
            self.containment_id = str(uuid.uuid4())
        if not self.tenant_id:
            self.tenant_id = "default"
        if not self.agent_id:
            self.agent_id = "default"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ContainmentRecord:
    """Current active containment state record for a single tenant and agent."""
    tenant_id: str = "default"
    agent_id: str = "default"
    current_state: str = ContainmentState.NORMAL
    isolation_level: str = IsolationLevel.NONE
    active_request: Optional[ContainmentRequest] = None
    state_history: List[Dict[str, Any]] = field(default_factory=list)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "current_state": self.current_state,
            "isolation_level": self.isolation_level,
            "active_request": self.active_request.to_dict() if self.active_request else None,
            "state_history_count": len(self.state_history),
            "state_history": self.state_history,
            "updated_at": self.updated_at,
        }


@dataclass
class GateDecision:
    """Decision output from the containment action gate."""
    allowed: bool
    decision: str  # ALLOW, DENY, REVIEW
    reason: str
    isolation_level: str = IsolationLevel.NONE
    containment_state: str = ContainmentState.NORMAL
    restricted_action: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
