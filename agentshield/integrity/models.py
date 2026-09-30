"""
Data models and integrity representations for Phase 23 Runtime Environment Integrity.
"""

from enum import Enum
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
import time
import uuid
import hashlib
import json

from agentshield.context.models import SecurityDecision


class IntegrityState(str, Enum):
    """Explicit runtime environment integrity classification states."""
    VALID = "VALID"
    DRIFTED = "DRIFTED"
    INVALID = "INVALID"
    REVIEW = "REVIEW"
    UNKNOWN = "UNKNOWN"


def compute_canonical_hash(payload: Dict[str, Any]) -> str:
    """Computes a canonical SHA-256 fingerprint for structured metadata dicts."""
    raw = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class RuntimeIntegrityBaseline:
    """Represents an approved security-relevant baseline state snapshot."""
    baseline_id: str = field(default_factory=lambda: f"base_{uuid.uuid4().hex[:8]}")
    agent_id: str = "default_agent"
    tenant_id: str = "default"
    capability_fingerprint: str = ""
    comm_policy_fingerprint: str = ""
    tool_fingerprints: Dict[str, str] = field(default_factory=dict)
    env_metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    baseline_hash: str = ""

    def __post_init__(self):
        if not self.baseline_hash:
            payload = {
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "capability_fingerprint": self.capability_fingerprint,
                "comm_policy_fingerprint": self.comm_policy_fingerprint,
                "tool_fingerprints": self.tool_fingerprints,
                "env_metadata": self.env_metadata,
            }
            self.baseline_hash = compute_canonical_hash(payload)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "capability_fingerprint": self.capability_fingerprint,
            "comm_policy_fingerprint": self.comm_policy_fingerprint,
            "tool_fingerprints": self.tool_fingerprints,
            "env_metadata": self.env_metadata,
            "created_at": self.created_at,
            "baseline_hash": self.baseline_hash,
        }


@dataclass
class RuntimeStateSnapshot:
    """Deterministic snapshot of active runtime security state."""
    snapshot_id: str = field(default_factory=lambda: f"snap_{uuid.uuid4().hex[:8]}")
    agent_id: str = "default_agent"
    tenant_id: str = "default"
    capability_fingerprint: str = ""
    comm_policy_fingerprint: str = ""
    tool_fingerprints: Dict[str, str] = field(default_factory=dict)
    env_metadata: Dict[str, Any] = field(default_factory=dict)
    captured_at: float = field(default_factory=time.time)
    snapshot_hash: str = ""

    def __post_init__(self):
        if not self.snapshot_hash:
            payload = {
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "capability_fingerprint": self.capability_fingerprint,
                "comm_policy_fingerprint": self.comm_policy_fingerprint,
                "tool_fingerprints": self.tool_fingerprints,
                "env_metadata": self.env_metadata,
            }
            self.snapshot_hash = compute_canonical_hash(payload)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "capability_fingerprint": self.capability_fingerprint,
            "comm_policy_fingerprint": self.comm_policy_fingerprint,
            "tool_fingerprints": self.tool_fingerprints,
            "env_metadata": self.env_metadata,
            "captured_at": self.captured_at,
            "snapshot_hash": self.snapshot_hash,
        }


@dataclass
class IntegrityCheckResult:
    """Security evaluation result of a runtime integrity verification."""
    check_id: str = field(default_factory=lambda: f"ichek_{uuid.uuid4().hex[:8]}")
    state: IntegrityState = IntegrityState.UNKNOWN
    decision: SecurityDecision = SecurityDecision.DENY
    allowed: bool = False
    reason: str = ""
    drift_details: Dict[str, Any] = field(default_factory=dict)
    violations: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "state": self.state.value,
            "decision": self.decision.value,
            "allowed": self.allowed,
            "reason": self.reason,
            "drift_details": self.drift_details,
            "violations": self.violations,
            "timestamp": self.timestamp,
        }
