"""
AgentShield HTTP Middleware Module.
"""

from typing import Callable, Any
from agentshield.core.config import ShieldConfig
from agentshield.core.pipeline import SecurityPipeline

class AgentShieldMiddleware:
    """WSGI/ASGI Middleware helper for shielding incoming API gateway requests."""

    def __init__(self, app: Any, config: ShieldConfig = None):
        self.app = app
        self.pipeline = SecurityPipeline(config=config or ShieldConfig())

    def __call__(self, environ: dict, start_response: Callable) -> Any:
        """WSGI interface entrypoint."""
        # Simple WSGI pass-through wrapper
        return self.app(environ, start_response)
