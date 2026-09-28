"""
Policy Rules & Constraints definitions.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class ToolConstraint:
    allowed_tools: List[str] = field(default_factory=list)
    blocked_tools: List[str] = field(default_factory=list)
    argument_patterns: Dict[str, List[str]] = field(default_factory=dict)

    def is_tool_allowed(self, tool_name: str) -> bool:
        if self.blocked_tools and tool_name in self.blocked_tools:
            return False
        if self.allowed_tools and tool_name not in self.allowed_tools:
            return False
        return True

@dataclass
class RateLimitRule:
    max_requests_per_minute: int = 60
    max_tool_calls_per_execution: int = 10
