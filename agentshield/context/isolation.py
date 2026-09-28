"""
Privilege Isolation Guard Module.
"""

from typing import Dict, Any, List

class PrivilegeIsolator:
    """Ensures user level inputs cannot escalate privilege or override system state."""

    ALLOWED_ROLES = {"admin", "user", "guest", "system"}

    def __init__(self, current_role: str = "user"):
        if current_role not in self.ALLOWED_ROLES:
            raise ValueError(f"Invalid role: {current_role}")
        self.current_role = current_role

    def validate_action_privilege(self, required_role: str) -> bool:
        """Validates if current context role satisfies action requirements."""
        role_hierarchy = {"guest": 1, "user": 2, "admin": 3, "system": 4}
        current_level = role_hierarchy.get(self.current_role, 0)
        required_level = role_hierarchy.get(required_role, 99)
        return current_level >= required_level

    def is_system_override_attempt(self, text: str) -> bool:
        """Detects explicit privilege escalation phrasing in user prompt."""
        forbidden_phrases = [
            "grant admin privileges",
            "sudo mode enabled",
            "switch role to system",
            "elevate privilege to root",
            "override security level"
        ]
        text_lower = text.lower()
        return any(phrase in text_lower for phrase in forbidden_phrases)
