"""
Memory Filter Module (Preventing sensitive data injection into long-term memory).
"""

from typing import Dict, Any, Tuple
from agentshield.security.sanitizer import InputOutputSanitizer
from agentshield.security.secrets import SecretDetector

class MemoryFilter:
    """Filters memory read/write payloads to prevent persisting sensitive data or exploits."""

    def __init__(self):
        self.sanitizer = InputOutputSanitizer(mask_pii=True)
        self.secret_detector = SecretDetector()

    def filter_memory_write(self, value: Any) -> Tuple[Any, bool]:
        """
        Sanitizes data prior to persisting in long-term memory.
        Returns (filtered_value, modified_flag).
        """
        if isinstance(value, str):
            # Check secrets first
            if self.secret_detector.detect_secrets(value)["has_secrets"]:
                value = self.secret_detector.redact_secrets(value)
            # Redact PII
            clean_text, stats = self.sanitizer.sanitize_input(value)
            was_modified = len(stats) > 0 or value != clean_text
            return clean_text, was_modified

        return value, False
