"""
Phase 24: Behavior Sequence Collector.
Bounded, isolated event history collector per tenant and agent.
"""

import time
import threading
from typing import Dict, Tuple, List, Optional
from agentshield.behavior.models import BehaviorEvent, BehaviorSequence


class BehaviorSequenceCollector:
    """
    Bounded thread-safe event sequence collector.
    Enforces strict tenant isolation and agent isolation.
    """

    def __init__(self, max_sequence_length: int = 100):
        self.max_sequence_length = max(1, max_sequence_length)
        # Map key: (tenant_id, agent_id) -> List[BehaviorEvent]
        self._sequences: Dict[Tuple[str, str], List[BehaviorEvent]] = {}
        # Track seen event IDs to handle duplicates: (tenant_id, agent_id) -> Set[str]
        self._seen_event_ids: Dict[Tuple[str, str], set] = {}
        self._lock = threading.Lock()

    def record_event(self, event: BehaviorEvent) -> BehaviorEvent:
        """
        Records a behavioral event into the agent's bounded sequence buffer.
        Enforces tenant & agent isolation and deduplication.
        """
        if event is None:
            raise ValueError("Cannot record a None event.")

        if not event.timestamp:
            event.timestamp = time.time()
        if not event.tenant_id:
            event.tenant_id = "default"
        if not event.agent_id:
            event.agent_id = "default"

        key = (event.tenant_id, event.agent_id)

        with self._lock:
            if key not in self._sequences:
                self._sequences[key] = []
                self._seen_event_ids[key] = set()

            # Duplicate check by event_id
            if event.event_id in self._seen_event_ids[key]:
                return event

            # Also check if exact identical event hash recorded at exact same timestamp
            event_hash = event.compute_event_hash()
            for existing in reversed(self._sequences[key]):
                if existing.event_id == event.event_id or (
                    existing.timestamp == event.timestamp and existing.compute_event_hash() == event_hash
                ):
                    return event

            # Append event
            self._sequences[key].append(event)
            self._seen_event_ids[key].add(event.event_id)

            # Enforce bounded sequence history (Invariant 7 - Bounded State)
            while len(self._sequences[key]) > self.max_sequence_length:
                removed_event = self._sequences[key].pop(0)
                self._seen_event_ids[key].discard(removed_event.event_id)

        return event

    def get_sequence(
        self, tenant_id: str = "default", agent_id: str = "default", limit: Optional[int] = None
    ) -> BehaviorSequence:
        """
        Retrieves the recorded behavioral sequence strictly isolated for (tenant_id, agent_id).
        """
        key = (tenant_id or "default", agent_id or "default")

        with self._lock:
            events = list(self._sequences.get(key, []))

        if limit is not None and limit > 0:
            events = events[-limit:]

        return BehaviorSequence(
            tenant_id=key[0],
            agent_id=key[1],
            events=events
        )

    def clear_sequence(self, tenant_id: str = "default", agent_id: str = "default") -> None:
        """Clears sequence for a specific agent and tenant."""
        key = (tenant_id or "default", agent_id or "default")
        with self._lock:
            self._sequences.pop(key, None)
            self._seen_event_ids.pop(key, None)

    def clear_all(self) -> None:
        """Resets all collected sequences."""
        with self._lock:
            self._sequences.clear()
            self._seen_event_ids.clear()

    def get_active_agent_count(self) -> int:
        """Returns count of active (tenant, agent) sequences tracked."""
        with self._lock:
            return len(self._sequences)

    def get_total_events_count(self) -> int:
        """Returns total events currently stored across all agents and tenants."""
        with self._lock:
            return sum(len(seq) for seq in self._sequences.values())
