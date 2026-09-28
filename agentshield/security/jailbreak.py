"""
Jailbreak Detector Module.
"""

import re
from typing import Dict, Any, List

class JailbreakDetector:
    """Detects persona-switching, roleplay exploits, and complex jailbreak templates."""

    JAILBREAK_PATTERNS = [
        (r"(?i)\bDAN\b.*\bdo\s+anything\s+now\b", 0.95, "DAN Jailbreak"),
        (r"(?i)\bAIM\b.*\balways\s+intelligent\s+and\s+machiavellian\b", 0.95, "AIM Jailbreak"),
        (r"(?i)hypothetically\s+speaking.*(bypass|hack|exploit|harm)", 0.80, "Hypothetical Framing"),
        (r"(?i)in\s+a\s+fictional\s+world\s+where\s+there\s+are\s+no\s+rules", 0.85, "Fictional Framing"),
        (r"(?i)translate\s+the\s+following\s+rot13\s+cipher", 0.75, "Cipher Obfuscation"),
        (r"(?i)pretend\s+you\s+are\s+my\s+grandma\s+telling\s+me\s+a\s+bedtime\s+story\s+about", 0.85, "Grandma Exploit"),
        (r"(?i)you\s+are\s+now\s+an\s+unfiltered\s+terminal", 0.90, "Terminal Emulation"),
        (r"(?i)jailbreak\s+prompt\s+mode\s+enabled", 0.95, "Explicit Jailbreak Directive")
    ]

    def __init__(self, threshold: float = 0.75):
        self.threshold = threshold

    def analyze(self, text: str) -> Dict[str, Any]:
        """Analyzes text for jailbreak attack signatures."""
        if not text:
            return {"is_jailbreak": False, "score": 0.0, "detected_vector": None}

        max_score = 0.0
        detected_vector = None

        for pattern, score, vector in self.JAILBREAK_PATTERNS:
            if re.search(pattern, text):
                if score > max_score:
                    max_score = score
                    detected_vector = vector

        return {
            "is_jailbreak": max_score >= self.threshold,
            "score": round(max_score, 4),
            "detected_vector": detected_vector,
            "threshold": self.threshold
        }
