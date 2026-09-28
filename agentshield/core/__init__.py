"""
Core AgentShield framework components.
"""

from agentshield.core.config import ShieldConfig
from agentshield.core.agent import ShieldedAgent, ShieldedResult
from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.interceptor import ToolInterceptor, shield_tool
from agentshield.core.exceptions import (
    AgentShieldError,
    SecurityViolationError,
    PolicyViolationError,
    SanitizationError,
    ContextBoundaryError,
    MemorySecurityError,
    RetrievalSecurityError
)

__all__ = [
    "ShieldConfig",
    "ShieldedAgent",
    "ShieldedResult",
    "SecurityPipeline",
    "ToolInterceptor",
    "shield_tool",
    "AgentShieldError",
    "SecurityViolationError",
    "PolicyViolationError",
    "SanitizationError",
    "ContextBoundaryError",
    "MemorySecurityError",
    "RetrievalSecurityError",
]
