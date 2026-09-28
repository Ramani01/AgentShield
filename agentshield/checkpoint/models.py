"""
Security Checkpoint and Rollback Models for AgentShield.
"""

import time
import uuid
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from agentshield.context.models import SecurityDecision, UserIdentity
from agentshield.security.tool_models import ToolBaseline

class CheckpointStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"
    RESTORED = "RESTORED"

class SecurityCheckpoint(BaseModel):
    """
    Immutable snapshot of an AgentShield security configuration state.
    Checkpoints only security configuration state (tool baselines, policy rules, shield config).
    Never checkpoints arbitrary user files, raw credentials, or private memory contents.
    """

    checkpoint_id: str = Field(default_factory=lambda: f"chk_{uuid.uuid4().hex[:12]}")
    created_at: float = Field(default_factory=time.time)
    created_by: str = "system"
    tenant_id: str = "default"
    description: str = ""
    state_fingerprint: str
    tool_baselines: Dict[str, ToolBaseline] = Field(default_factory=dict)
    policy_snapshot: Dict[str, Any] = Field(default_factory=dict)
    configuration_snapshot: Dict[str, Any] = Field(default_factory=dict)
    provenance_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    status: CheckpointStatus = CheckpointStatus.ACTIVE

class RollbackRequest(BaseModel):
    """Explicit request to restore a previously created security checkpoint."""

    checkpoint_id: str
    requested_by: str
    tenant_id: str = "default"
    reason: str = ""
    authorization_context: Dict[str, Any] = Field(default_factory=dict)
    requested_at: float = Field(default_factory=time.time)

class RollbackResult(BaseModel):
    """Result of a security checkpoint rollback operation."""

    rollback_id: str = Field(default_factory=lambda: f"rlb_{uuid.uuid4().hex[:12]}")
    checkpoint_id: str
    decision: SecurityDecision = SecurityDecision.DENY
    restored: bool = False
    reason: str = ""
    previous_state_fingerprint: Optional[str] = None
    restored_state_fingerprint: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)
    audit_event_id: Optional[str] = None
    tenant_id: str = "default"
