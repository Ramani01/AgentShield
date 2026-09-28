"""
AgentShield exception definitions.
"""

class AgentShieldError(Exception):
    """Base exception for all AgentShield errors."""
    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

class SecurityViolationError(AgentShieldError):
    """Raised when a security threat (e.g. prompt injection, secret leak) is detected."""
    pass

class PolicyViolationError(AgentShieldError):
    """Raised when an operation violates configured security policies."""
    pass

class SanitizationError(AgentShieldError):
    """Raised when data sanitization fails."""
    pass

class ContextBoundaryError(AgentShieldError):
    """Raised when context isolation boundaries are breached."""
    pass

class MemorySecurityError(AgentShieldError):
    """Raised when memory tampering or unauthorized access occurs."""
    pass

class RetrievalSecurityError(AgentShieldError):
    """Raised when a retrieved document is identified as poisoned or forbidden."""
    pass
