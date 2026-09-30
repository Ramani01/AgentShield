"""
AgentShield Capabilities & Privilege Model Package (Phase 21).
"""

from agentshield.capabilities.models import (
    AgentCapability,
    CapabilityGrant,
    AgentCapabilityProfile,
    CapabilityCheckRequest,
    CapabilityCheckResult
)
from agentshield.capabilities.engine import CapabilityEngine

__all__ = [
    "AgentCapability",
    "CapabilityGrant",
    "AgentCapabilityProfile",
    "CapabilityCheckRequest",
    "CapabilityCheckResult",
    "CapabilityEngine"
]
