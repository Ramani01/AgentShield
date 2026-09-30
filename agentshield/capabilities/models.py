"""
Agent Capability & Privilege Data Models for AgentShield v2 (Phase 21).
"""

import time
import uuid
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from agentshield.context.models import SecurityDecision, UserIdentity


class AgentCapability(str, Enum):
    """Explicit system capabilities governing authorized agent operations."""
    READ_DOCUMENTS = "READ_DOCUMENTS"
    READ_MEMORY = "READ_MEMORY"
    WRITE_MEMORY = "WRITE_MEMORY"
    USE_TOOLS = "USE_TOOLS"
    EXECUTE_ACTIONS = "EXECUTE_ACTIONS"
    EXTERNAL_COMMUNICATION = "EXTERNAL_COMMUNICATION"
    DATA_EXPORT = "DATA_EXPORT"
    MODIFY_CONFIGURATION = "MODIFY_CONFIGURATION"
    CREATE_CHECKPOINT = "CREATE_CHECKPOINT"
    ROLLBACK_CHECKPOINT = "ROLLBACK_CHECKPOINT"


class CapabilityGrant(BaseModel):
    """Represents an explicit capability grant with optional target constraints."""
    capability: AgentCapability
    granted: bool = True
    allowed_targets: List[str] = Field(default_factory=list)  # Specific tool IDs, domains, memory keys
    conditions: Dict[str, Any] = Field(default_factory=dict)
    reason: str = "Explicit administrative grant"

    model_config = {"frozen": False}


class AgentCapabilityProfile(BaseModel):
    """
    Immutable authorization profile defining least-privilege capability grants for an AI agent.
    Strictly isolated from runtime user prompts, RAG documents, and model outputs.
    """
    profile_id: str = Field(default_factory=lambda: f"prof_{uuid.uuid4().hex[:12]}")
    agent_id: str = "default_agent"
    tenant_id: str = "default"
    grants: Dict[AgentCapability, CapabilityGrant] = Field(default_factory=dict)
    is_immutable: bool = True
    created_at: float = Field(default_factory=time.time)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": False}

    def is_capability_granted(self, capability: AgentCapability, target: Optional[str] = None) -> bool:
        """Checks if a capability is explicitly granted under least-privilege rules."""
        grant = self.grants.get(capability)
        if not grant or not grant.granted:
            return False

        if target and grant.allowed_targets:
            if target not in grant.allowed_targets and "*" not in grant.allowed_targets:
                return False

        return True


class CapabilityCheckRequest(BaseModel):
    """Request structure for validating capability authorization."""
    capability: AgentCapability
    agent_id: str = "default_agent"
    tenant_id: str = "default"
    target: Optional[str] = None
    identity: Optional[UserIdentity] = None
    context_data: Dict[str, Any] = Field(default_factory=dict)


class CapabilityCheckResult(BaseModel):
    """Result of capability authorization check."""
    check_id: str = Field(default_factory=lambda: f"chk_{uuid.uuid4().hex[:12]}")
    capability: AgentCapability
    allowed: bool = False
    decision: SecurityDecision = SecurityDecision.DENY
    reason: str = ""
    violations: List[str] = Field(default_factory=list)
    timestamp: float = Field(default_factory=time.time)
