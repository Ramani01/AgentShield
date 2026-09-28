"""
FastAPI Integration Dependencies, Decorators, and Route Helpers.
"""

from typing import Callable, Any, Optional
from agentshield.integration.models import ShieldIdentity, ShieldResponse, ShieldDecision
from agentshield.integration.adapter import AgentShieldAdapter

try:
    from fastapi import Request, HTTPException, Depends
except ImportError:
    Request = Any
    HTTPException = Any
    Depends = Any


def get_security_context(request: Request) -> ShieldIdentity:
    """
    FastAPI dependency returning the extracted ShieldIdentity from request state.
    Raises HTTP 403 Forbidden if security identity is missing or unauthenticated.
    """
    identity = getattr(getattr(request, "state", None), "security_identity", None)
    if not identity:
        raise HTTPException(
            status_code=403,
            detail={
                "decision": ShieldDecision.DENY.value,
                "allowed": False,
                "reason": "Security Context Missing: Request state has no propagated security identity."
            }
        )
    return identity


def guard_fastapi_endpoint(adapter: Optional[AgentShieldAdapter] = None) -> Callable:
    """
    Decorator for guarding FastAPI endpoint handlers with AgentShield output sanitization
    and policy enforcement.
    """
    adapter_inst = adapter or AgentShieldAdapter()

    def decorator(fn: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            # Execute original endpoint handler
            res = await fn(*args, **kwargs) if callable(fn) else fn(*args, **kwargs)

            # If response is string or dict containing output, inspect output
            if isinstance(res, str):
                return adapter_inst.pipeline.inspect_output(res)
            elif isinstance(res, dict) and "output" in res and isinstance(res["output"], str):
                res["output"] = adapter_inst.pipeline.inspect_output(res["output"])
            return res

        return wrapper

    return decorator
