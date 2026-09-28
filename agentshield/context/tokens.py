"""
Token Budget & Sliding Window Manager Module.
"""

from typing import List, Dict, Any

class TokenManager:
    """Manages token counts, budget limits, and context truncation."""

    def __init__(self, max_token_budget: int = 4096):
        self.max_token_budget = max_token_budget

    def estimate_token_count(self, text: str) -> int:
        """Estimates token length (approx 4 characters per token)."""
        if not text:
            return 0
        return max(1, len(text) // 4)

    def enforce_budget(self, text: str) -> Dict[str, Any]:
        """Truncates text if it exceeds the maximum token budget."""
        tokens = self.estimate_token_count(text)
        if tokens <= self.max_token_budget:
            return {
                "text": text,
                "token_count": tokens,
                "truncated": False
            }

        # Truncate character string to budget
        max_chars = self.max_token_budget * 4
        truncated_text = text[:max_chars] + "... [TRUNCATED_BY_AGENTSHIELD]"
        return {
            "text": truncated_text,
            "token_count": self.max_token_budget,
            "truncated": True
        }
