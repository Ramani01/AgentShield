"""
Policy Engine Module.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
from agentshield.policies.parser import PolicyParser
from agentshield.policies.rules import ToolConstraint, RateLimitRule
from agentshield.core.exceptions import PolicyViolationError

class PolicyEngine:
    """Evaluates agent tool calls, actions, and limits against configured policies."""

    def __init__(self, policy_file_path: Optional[str] = None, policy_data: Optional[Dict[str, Any]] = None):
        if policy_file_path:
            self.policy_data = PolicyParser.load_from_file(policy_file_path)
        elif policy_data:
            self.policy_data = policy_data
        else:
            default_yaml = Path("configs/default_policy.yaml")
            if default_yaml.exists():
                self.policy_data = PolicyParser.load_from_file(str(default_yaml))
            else:
                self.policy_data = {
                    "global": {"strict_mode": True},
                    "tool_constraints": {
                        "allowed_tools": ["search_web", "read_file", "calculate", "summarize"],
                        "blocked_tools": ["exec_bash", "drop_database", "raw_eval"]
                    }
                }

        self.tool_constraints = PolicyParser.parse_tool_constraints(self.policy_data)
        self.rate_limits = PolicyParser.parse_rate_limits(self.policy_data)

    def evaluate_tool_execution(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates whether a tool call is permitted by policy rules.
        Raises PolicyViolationError if blocked and strict mode is active.
        """
        if not self.tool_constraints.is_tool_allowed(tool_name):
            err_msg = f"Policy Violation: Tool '{tool_name}' is forbidden by security policy."
            return {"allowed": False, "reason": err_msg}

        # Check argument level forbidden patterns if configured
        arg_patterns = self.tool_constraints.argument_patterns.get(tool_name, {})
        forbidden_paths = arg_patterns.get("forbidden_paths", [])

        arg_str = str(arguments)
        for pattern in forbidden_paths:
            pattern_clean = pattern.replace("*", "")
            if pattern_clean and pattern_clean in arg_str:
                err_msg = f"Policy Violation: Tool '{tool_name}' argument matched forbidden path pattern '{pattern}'."
                return {"allowed": False, "reason": err_msg}

        return {"allowed": True, "reason": "Operation permitted by policy."}
