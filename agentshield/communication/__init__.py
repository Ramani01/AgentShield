"""
Phase 22: Agent Communication & Service Policy module.
"""

from agentshield.communication.models import (
    PrincipalType,
    CommunicationType,
    CommunicationPrincipal,
    CommunicationPolicyRule,
    CommunicationRequest,
    CommunicationDecisionResult
)
from agentshield.communication.engine import CommunicationPolicyEngine

__all__ = [
    "PrincipalType",
    "CommunicationType",
    "CommunicationPrincipal",
    "CommunicationPolicyRule",
    "CommunicationRequest",
    "CommunicationDecisionResult",
    "CommunicationPolicyEngine"
]
