"""
Integration Request and Response Models for AgentShield.
"""

import time
from enum import Enum
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

from agentshield.context.models import TrustLevel, UserIdentity, SecurityDecision, InstructionType, SourceCategory, ContextItem


class ShieldDecision(str, Enum):
    """Explicit security decisions returned by AgentShield integration layer."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    REVIEW = "REVIEW"
    ISOLATE = "ISOLATE"


class ShieldIdentity(BaseModel):
    """Structured identity and tenant scope for request propagation."""
    user_id: str = "anonymous"
    tenant_id: str = "default"
    roles: List[str] = Field(default_factory=list)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_user_identity(self) -> UserIdentity:
        """Converts to internal UserIdentity context model."""
        return UserIdentity(
            user_id=self.user_id,
            tenant_id=self.tenant_id,
            roles=self.roles,
            trust_level=self.trust_level
        )


class ShieldRequest(BaseModel):
    """Incoming request payload for pre-execution security evaluation."""
    prompt: str
    identity: Optional[ShieldIdentity] = None
    context_items: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ShieldOutputRequest(BaseModel):
    """Outgoing agent output payload for post-execution security validation."""
    output_text: str
    identity: Optional[ShieldIdentity] = None
    recipient: Optional[str] = None
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ShieldActionRequest(BaseModel):
    """Proposed tool or system action payload for action validation."""
    action_type: str
    tool_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    identity: Optional[ShieldIdentity] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ShieldResponse(BaseModel):
    """Unified security inspection response returned by integration layer."""
    decision: ShieldDecision
    allowed: bool
    sanitized_content: Optional[str] = None
    reason: Optional[str] = None
    violations: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)
