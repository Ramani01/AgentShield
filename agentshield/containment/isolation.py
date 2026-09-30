"""
Phase 25: Isolation State Manager.
Thread-safe manager for tracking agent containment states and enforcing transition constraints.
"""

import time
import threading
import logging
from typing import Dict, Tuple, List, Optional, Any
from agentshield.containment.models import (
    ContainmentState,
    IsolationLevel,
    ContainmentRequest,
    ContainmentRecord,
    validate_state_transition,
    InvalidStateTransitionError
)

logger = logging.getLogger("AgentShield.IsolationStateManager")


class IsolationStateManager:
    """
    Thread-safe manager enforcing tenant and agent isolation for containment states.
    Invariants Enforced:
    1. Tenant Isolation: Tenant A cannot alter Tenant B's agent containment state.
    2. Agent Isolation: Agent A cannot alter Agent B's containment state.
    9. Idempotency: Duplicate/repeated containment requests are safe and idempotent.
    10. Valid State Transitions: Rejects invalid state machine transitions.
    """

    def __init__(self):
        # Key: (tenant_id, agent_id) -> ContainmentRecord
        self._records: Dict[Tuple[str, str], ContainmentRecord] = {}
        self._lock = threading.Lock()

    def get_record(self, tenant_id: str = "default", agent_id: str = "default") -> ContainmentRecord:
        """
        Retrieves current ContainmentRecord for (tenant_id, agent_id).
        Returns a new record in NORMAL state if none exists.
        """
        key = (tenant_id or "default", agent_id or "default")
        with self._lock:
            if key not in self._records:
                self._records[key] = ContainmentRecord(
                    tenant_id=key[0],
                    agent_id=key[1],
                    current_state=ContainmentState.NORMAL,
                    isolation_level=IsolationLevel.NONE,
                    updated_at=time.time()
                )
            return self._records[key]

    def transition_state(
        self,
        tenant_id: str,
        agent_id: str,
        target_state: str,
        isolation_level: str = IsolationLevel.FULL,
        request: Optional[ContainmentRequest] = None
    ) -> ContainmentRecord:
        """
        Executes a validated containment state transition.
        Enforces tenant/agent isolation, state machine rules, and idempotency.
        """
        key = (tenant_id or "default", agent_id or "default")

        with self._lock:
            record = self._records.get(key)
            if not record:
                record = ContainmentRecord(
                    tenant_id=key[0],
                    agent_id=key[1],
                    current_state=ContainmentState.NORMAL,
                    isolation_level=IsolationLevel.NONE,
                    updated_at=time.time()
                )
                self._records[key] = record

            current_state = record.current_state

            # Idempotency check (Invariant 9):
            if current_state == target_state and target_state == ContainmentState.CONTAINED:
                # Update active request and timestamp without adding corrupt duplicate state transitions
                if request:
                    record.active_request = request
                record.isolation_level = isolation_level
                record.updated_at = time.time()
                logger.info(f"Idempotent containment update for agent '{key[1]}' in tenant '{key[0]}'.")
                return record

            # Validate State Transition (Invariant 10)
            validate_state_transition(from_state=current_state, to_state=target_state)

            # Record state history
            history_entry = {
                "from_state": current_state,
                "to_state": target_state,
                "isolation_level": isolation_level,
                "timestamp": time.time(),
                "reason": request.reason if request else "State transition",
                "request_id": request.containment_id if request else None,
                "principal_id": request.principal_id if request else None
            }
            record.state_history.append(history_entry)

            # Update current state
            record.current_state = target_state
            record.isolation_level = isolation_level
            record.active_request = request if target_state in (ContainmentState.CONTAINED, ContainmentState.SUSPECTED) else record.active_request
            record.updated_at = time.time()

            logger.info(
                f"Transitioned agent '{key[1]}' (Tenant: '{key[0]}') from '{current_state}' to '{target_state}' "
                f"(Level: {isolation_level})."
            )
            return record

    def list_active_containments(self) -> List[ContainmentRecord]:
        """Returns all records currently in CONTAINED or SUSPECTED states."""
        with self._lock:
            return [
                rec for rec in self._records.values()
                if rec.current_state in (ContainmentState.CONTAINED, ContainmentState.SUSPECTED)
            ]

    def clear(self) -> None:
        """Resets all records."""
        with self._lock:
            self._records.clear()
