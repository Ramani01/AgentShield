"""
Secret & Credential Leak Detector Module.
"""

import re
from typing import Dict, Any, List

class SecretDetector:
    """Scans text for leaked API keys, credentials, tokens, and cryptographic keys."""

    SECRET_PATTERNS = {
        "aws_access_key": (r"\bAKIA[0-9A-Z]{16}\b", "AWS Access Key"),
        "openai_api_key": (r"\bsk-[a-zA-Z0-9]{32,64}\b", "OpenAI API Key"),
        "github_token": (r"\bghp_[a-zA-Z0-9]{36}\b", "GitHub Personal Access Token"),
        "generic_secret": (r"(?i)(api_key|secret_key|private_key|token|auth_header)\s*[:=]\s*['\"]([a-zA-Z0-9_-]{16,64})['\"]", "Generic API Secret"),
        "rsa_private_key": (r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----", "RSA Private Key Block"),
        "jwt_token": (r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b", "JSON Web Token (JWT)")
    }

    def detect_secrets(self, text: str) -> Dict[str, Any]:
        """Detects presence of credentials or secrets in text."""
        if not text:
            return {"has_secrets": False, "findings": []}

        findings = []

        for key_type, (pattern, description) in self.SECRET_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                findings.append({
                    "secret_type": key_type,
                    "description": description,
                    "count": len(matches)
                })

        return {
            "has_secrets": len(findings) > 0,
            "findings": findings
        }

    def redact_secrets(self, text: str) -> str:
        """Redacts all detected secrets from text."""
        if not text:
            return text

        redacted = text
        for key_type, (pattern, description) in self.SECRET_PATTERNS.items():
            redacted = re.sub(pattern, f"[REDACTED_{key_type.upper()}]", redacted)

        return redacted
