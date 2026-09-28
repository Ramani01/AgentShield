"""
Tool Interceptor & Middleware Decorators Module.
"""

from functools import wraps
from typing import Callable, Any, Dict, Optional
from agentshield.security.vulnerabilities import VulnerabilityScanner
from agentshield.policies.engine import PolicyEngine
from agentshield.core.exceptions import SecurityViolationError, PolicyViolationError

class ToolInterceptor:
    """Interceptors for agent tool calls and dynamic actions."""

    def __init__(self, policy_engine: Optional[PolicyEngine] = None):
        self.vuln_scanner = VulnerabilityScanner()
        self.policy_engine = policy_engine or PolicyEngine()

    def shield_tool(self, tool_name: Optional[str] = None):
        """Decorator to guard tool executions against policy violations and injection attacks."""
        def decorator(fn: Callable[..., Any]):
            name = tool_name or fn.__name__

            @wraps(fn)
            def wrapper(*args, **kwargs):
                # 1. Evaluate policy permissions
                pol_res = self.policy_engine.evaluate_tool_execution(name, kwargs)
                if not pol_res["allowed"]:
                    raise PolicyViolationError(pol_res["reason"])

                # 2. Evaluate vulnerability risks
                vuln_res = self.vuln_scanner.scan_tool_call(name, kwargs)
                if vuln_res["is_vulnerable"]:
                    threat_desc = ", ".join([t["risk_type"] for t in vuln_res["threats"]])
                    raise SecurityViolationError(f"Tool execution blocked due to security risks: {threat_desc}")

                return fn(*args, **kwargs)
            return wrapper
        return decorator

# Global default interceptor instance
interceptor = ToolInterceptor()
shield_tool = interceptor.shield_tool
