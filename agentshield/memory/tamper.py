"""
Memory Tamper Detector Module.
"""

import hashlib
from typing import Dict, Any

class TamperDetector:
    """Detects out-of-band memory tampering or embedding alterations."""

    @staticmethod
    def generate_signature(data: str, secret_salt: str = "agentshield_salt") -> str:
        """Generates SHA-256 HMAC-style signature for stored memory items."""
        salted = f"{secret_salt}:{data}"
        return hashlib.sha256(salted.encode("utf-8")).hexdigest()

    @staticmethod
    def verify_signature(data: str, signature: str, secret_salt: str = "agentshield_salt") -> bool:
        """Verifies integrity of data against a signature."""
        expected = TamperDetector.generate_signature(data, secret_salt)
        return expected == signature
