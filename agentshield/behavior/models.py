"""
Phase 24: Multi-Step Behavioral Detection Models.
"""

import time
import uuid
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional


class BehaviorEventType:
    """Standard normalized behavioral event types."""
    READ_DOCUMENT = "READ_DOCUMENT"
    READ_MEMORY = "READ_MEMORY"
    WRITE_MEMORY = "WRITE_MEMORY"
    USE_TOOL = "USE_TOOL"
    EXECUTE_ACTION = "EXECUTE_ACTION"
    EXTERNAL_COMMUNICATION = "EXTERNAL_COMMUNICATION"
    DATA_EXPORT = "DATA_EXPORT"
    MODIFY_CONFIGURATION = "MODIFY_CONFIGURATION"
    CREATE_CHECKPOINT = "CREATE_CHECKPOINT"
    ROLLBACK_CHECKPOINT = "ROLLBACK_CHECKPOINT"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def all_types(cls) -> List[str]:
        return [
            cls.READ_DOCUMENT,
            cls.READ_MEMORY,
            cls.WRITE_MEMORY,
            cls.USE_TOOL,
            cls.EXECUTE_ACTION,
            cls.EXTERNAL_COMMUNICATION,
            cls.DATA_EXPORT,
            cls.MODIFY_CONFIGURATION,
            cls.CREATE_CHECKPOINT,
            cls.ROLLBACK_CHECKPOINT,
            cls.UNKNOWN,
        ]


@dataclass
class BehaviorEvent:
    """Normalized observable agent behavior event."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    tenant_id: str = "default"
    agent_id: str = "default"
    principal_id: Optional[str] = None
    event_type: str = BehaviorEventType.READ_DOCUMENT
    resource: Optional[str] = None
    capability: Optional[str] = None
    communication_target: Optional[str] = None
    trust_level: Optional[str] = None
    runtime_integrity_state: Optional[str] = None
    source_control: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()
        if not self.event_id:
            self.event_id = str(uuid.uuid4())
        if not self.tenant_id:
            self.tenant_id = "default"
        if not self.agent_id:
            self.agent_id = "default"

    def compute_event_hash(self) -> str:
        """Computes a deterministic SHA-256 hash of the normalized event content."""
        payload = {
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "principal_id": self.principal_id,
            "event_type": self.event_type,
            "resource": self.resource,
            "capability": self.capability,
            "communication_target": self.communication_target,
            "trust_level": self.trust_level,
            "runtime_integrity_state": self.runtime_integrity_state,
            "source_control": self.source_control,
            "metadata": self.metadata,
        }
        raw = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Returns a dict representation of the event."""
        res = asdict(self)
        res["event_hash"] = self.compute_event_hash()
        return res


@dataclass
class BehaviorSequence:
    """Ordered sequence of behavioral events for a single agent and tenant."""
    sequence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default"
    agent_id: str = "default"
    events: List[BehaviorEvent] = field(default_factory=list)

    def to_canonical_string(self) -> str:
        """Returns canonical arrow-delimited sequence of event types."""
        return " -> ".join([e.event_type for e in self.events])

    def compute_canonical_sequence_hash(self) -> str:
        """Computes deterministic SHA-256 hash of the canonical sequence."""
        payload = {
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "canonical_sequence": self.to_canonical_string(),
            "event_hashes": [e.compute_event_hash() for e in self.events],
        }
        raw = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence_id": self.sequence_id,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "canonical_sequence": self.to_canonical_string(),
            "sequence_hash": self.compute_canonical_sequence_hash(),
            "event_count": len(self.events),
            "events": [e.to_dict() for e in self.events],
        }


@dataclass
class BehaviorAssessment:
    """Structured assessment result of behavioral pattern detection."""
    matched: bool = False
    pattern_id: Optional[str] = None
    pattern_name: Optional[str] = None
    risk_level: str = "LOW"
    confidence: float = 0.0
    recommended_decision: str = "ALLOW"
    matched_events: List[BehaviorEvent] = field(default_factory=list)
    matched_sequence_ids: List[str] = field(default_factory=list)
    runtime_integrity_state: Optional[str] = None
    runtime_baseline_reference: Optional[str] = None
    runtime_snapshot_reference: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "matched": self.matched,
            "pattern_id": self.pattern_id,
            "pattern_name": self.pattern_name,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "recommended_decision": self.recommended_decision,
            "matched_events_count": len(self.matched_events),
            "matched_events": [e.to_dict() for e in self.matched_events],
            "matched_sequence_ids": self.matched_sequence_ids,
            "runtime_integrity_state": self.runtime_integrity_state,
            "runtime_baseline_reference": self.runtime_baseline_reference,
            "runtime_snapshot_reference": self.runtime_snapshot_reference,
            "details": self.details,
        }
