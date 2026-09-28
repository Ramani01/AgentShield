"""
AgentShield Integration & API Framework Package.
"""

from agentshield.integration.models import (
    ShieldDecision,
    ShieldIdentity,
    ShieldRequest,
    ShieldOutputRequest,
    ShieldActionRequest,
    ShieldResponse
)
from agentshield.integration.adapter import AgentShieldAdapter
from agentshield.integration.middleware import AgentShieldMiddleware
from agentshield.integration.fastapi import (
    get_security_context,
    guard_fastapi_endpoint
)

__all__ = [
    "ShieldDecision",
    "ShieldIdentity",
    "ShieldRequest",
    "ShieldOutputRequest",
    "ShieldActionRequest",
    "ShieldResponse",
    "AgentShieldAdapter",
    "AgentShieldMiddleware",
    "get_security_context",
    "guard_fastapi_endpoint"
]
