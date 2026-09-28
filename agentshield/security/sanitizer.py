"""
Input & Output Data Sanitizer Module (PII & Code Sanitization).
"""

import re
from typing import Dict, Any, Tuple

class InputOutputSanitizer:
    """Sanitizes inputs and outputs by redacting PII and masking sensitive tokens."""

    PII_PATTERNS = {
        "email": (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[REDACTED_EMAIL]"),
        "ssn": (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
        "credit_card": (r"\b(?:\d[ -]*?){13,16}\b", "[REDACTED_CREDIT_CARD]"),
        "phone_us": (r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "[REDACTED_PHONE]"),
        "ip_address": (r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "[REDACTED_IP]"),
    }

    def __init__(self, mask_pii: bool = True):
        self.mask_pii = mask_pii

    def sanitize_input(self, text: str) -> Tuple[str, Dict[str, int]]:
        """Sanitizes user inputs, removing HTML tags and optionally redacting PII."""
        if not text:
            return text, {}

        stats = {}
        cleaned_text = text

        if self.mask_pii:
            for pii_type, (pattern, replacement) in self.PII_PATTERNS.items():
                matches = len(re.findall(pattern, cleaned_text))
                if matches > 0:
                    stats[pii_type] = matches
                    cleaned_text = re.sub(pattern, replacement, cleaned_text)

        # Basic HTML tag stripping for prompt protection
        cleaned_text = re.sub(r"<script.*?>.*?</script>", "", cleaned_text, flags=re.DOTALL | re.IGNORECASE)

        return cleaned_text, stats

    def sanitize_output(self, text: str) -> Tuple[str, Dict[str, int]]:
        """Sanitizes agent output to prevent accidental PII leaks."""
        return self.sanitize_input(text)
