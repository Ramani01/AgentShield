"""
Policy YAML & JSON Parser Module.
"""

import json
import yaml
from pathlib import Path
from typing import Dict, Any
from agentshield.policies.rules import ToolConstraint, RateLimitRule

class PolicyParser:
    """Parses policy configuration files (YAML/JSON) into Policy objects."""

    @staticmethod
    def load_from_file(file_path: str) -> Dict[str, Any]:
        """Loads and parses a YAML or JSON policy file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {file_path}")

        content = path.read_text(encoding="utf-8")
        if path.suffix.lower() in [".yaml", ".yml"]:
            data = yaml.safe_load(content)
        elif path.suffix.lower() == ".json":
            data = json.loads(content)
        else:
            raise ValueError(f"Unsupported policy format: {path.suffix}")

        return data or {}

    @staticmethod
    def parse_tool_constraints(policy_data: Dict[str, Any]) -> ToolConstraint:
        """Extracts tool constraints from raw policy dict."""
        tc = policy_data.get("tool_constraints", {})
        return ToolConstraint(
            allowed_tools=tc.get("allowed_tools", []),
            blocked_tools=tc.get("blocked_tools", []),
            argument_patterns=tc.get("tool_arguments", {})
        )

    @staticmethod
    def parse_rate_limits(policy_data: Dict[str, Any]) -> RateLimitRule:
        """Extracts rate limits from raw policy dict."""
        rl = policy_data.get("rate_limits", {})
        return RateLimitRule(
            max_requests_per_minute=rl.get("max_requests_per_minute", 60),
            max_tool_calls_per_execution=rl.get("max_tool_calls_per_execution", 10)
        )
