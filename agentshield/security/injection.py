"""
Prompt Injection Detection Module (Trust-Aware & Category-Based Detection).
"""

import re
import base64
from typing import Dict, Any, List, Optional
from agentshield.context.models import TrustLevel, SourceCategory, SecurityDecision
from agentshield.security.models import (
    RiskLevel,
    InjectionCategory,
    PromptInjectionResult
)

class PromptInjectionScanner:
    """Legacy/Base scanner maintaining backwards compatibility for existing calls."""

    DEFAULT_INJECTION_PATTERNS = [
        (r"(?i)ignore\s+(all\s+)?(previous|prior)\s+(instructions|directives|prompts)", 0.95),
        (r"(?i)disregard\s+(all\s+)?(previous|prior)\s+(system|user)\s+(rules|prompts)", 0.90),
        (r"(?i)you\s+are\s+now\s+in\s+developer\s+mode", 0.90),
        (r"(?i)system\s*(:|\s+)\s*override", 0.85),
        (r"(?i)do\s+anything\s+now", 0.85),
        (r"(?i)forget\s+everything\s+you\s+were\s+told", 0.90),
        (r"(?i)act\s+as\s+an\s+unrestricted\s+AI", 0.85),
        (r"(?i)bypass\s+(safety|security)\s+(filters|rules|guardrails)", 0.95),
        (r"(?i)output\s+the\s+system\s+prompt", 0.80),
        (r"(?i)reveal\s+your\s+initial\s+instructions", 0.80),
        (r"(?i)\[\s*system\s*note\s*:.*\]", 0.75),
        (r"(?i)<\s*system\s*>.*<\s*/\s*system\s*>", 0.80),
    ]

    def __init__(self, threshold: float = 0.70, custom_patterns: List[tuple] = None):
        self.threshold = threshold
        self.patterns = self.DEFAULT_INJECTION_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)

    def scan(self, text: str) -> Dict[str, Any]:
        """Scans text for prompt injection markers."""
        if not text:
            return {"is_injection": False, "max_score": 0.0, "matches": []}

        matches = []
        max_score = 0.0

        for pattern, score in self.patterns:
            found = re.findall(pattern, text)
            if found:
                max_score = max(max_score, score)
                matches.append({
                    "pattern": pattern,
                    "score": score,
                    "count": len(found)
                })

        is_injection = max_score >= self.threshold

        return {
            "is_injection": is_injection,
            "max_score": round(max_score, 4),
            "matches": matches,
            "threshold": self.threshold
        }


class PromptInjectionDetector:
    """
    Defensive, trust-aware prompt injection detector returning structured result analysis,
    confidence scoring, and category breakdown.
    """

    CATEGORY_PATTERNS = [
        # Instruction Override
        (
            r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|existing)\s+(instructions|directives|rules|prompts)",
            InjectionCategory.INSTRUCTION_OVERRIDE,
            0.95
        ),
        (
            r"(?i)you\s+are\s+now\s+in\s+developer\s+mode",
            InjectionCategory.INSTRUCTION_OVERRIDE,
            0.90
        ),
        (
            r"(?i)act\s+as\s+an\s+unrestricted\s+AI",
            InjectionCategory.INSTRUCTION_OVERRIDE,
            0.90
        ),

        # System Impersonation
        (
            r"(?i)(<\|system_context\|>|\[\s*system\s*(context|prompt|instruction|note)\s*\]|<\s*system\s*>)",
            InjectionCategory.SYSTEM_IMPERSONATION,
            0.90
        ),
        (
            r"(?i)system\s*(:|\s+)\s*override",
            InjectionCategory.SYSTEM_IMPERSONATION,
            0.85
        ),

        # Priority Manipulation
        (
            r"(?i)override\s+(system\s+)?priority",
            InjectionCategory.PRIORITY_MANIPULATION,
            0.85
        ),
        (
            r"(?i)highest\s+precedence\s+rule\s*:",
            InjectionCategory.PRIORITY_MANIPULATION,
            0.85
        ),

        # Prompt Extraction
        (
            r"(?i)(output|reveal|print|show)\s+(the\s+)?(system|initial|developer)\s+(prompt|instructions)",
            InjectionCategory.PROMPT_EXTRACTION,
            0.85
        ),

        # Boundary Bypass
        (
            r"(?i)bypass\s+(safety|security)\s+(filters|rules|guardrails)",
            InjectionCategory.BOUNDARY_BYPASS,
            0.95
        ),
        (
            r"(?i)disable\s+security\s+checks",
            InjectionCategory.BOUNDARY_BYPASS,
            0.90
        ),

        # Metadata Manipulation
        (
            r"(?i)(TRUST_LEVEL\s*=\s*TRUSTED|security_level\s*:\s*trusted|admin\s+says\s+this\s+is\s+trusted)",
            InjectionCategory.METADATA_MANIPULATION,
            0.95
        ),
        (
            r"(?i)grant\s+trusted\s+status",
            InjectionCategory.METADATA_MANIPULATION,
            0.90
        ),

        # State Tampering
        (
            r"(?i)(overwrite|wipe|clear)\s+(memory\s+store|audit\s+log|security\s+state)",
            InjectionCategory.STATE_TAMPERING,
            0.90
        ),

        # Tool Injection
        (
            r"(?i)(tool_call\s*:|run\s+bash\s+command|execute\s+tool\s+drop\s+table)",
            InjectionCategory.TOOL_INJECTION,
            0.85
        ),
    ]

    def __init__(self, critical_threshold: float = 0.85, high_threshold: float = 0.70):
        self.critical_threshold = critical_threshold
        self.high_threshold = high_threshold
        self.legacy_scanner = PromptInjectionScanner(threshold=high_threshold)

    def detect(
        self,
        text: str,
        trust_level: Optional[TrustLevel] = None,
        source_category: Optional[SourceCategory] = None
    ) -> PromptInjectionResult:
        """
        Runs trust-aware detection on input text, considering origin trust level to avoid
        false positives on trusted system/developer instructions.
        """
        if not text or not text.strip():
            return PromptInjectionResult(
                detected=False,
                risk_level=RiskLevel.LOW,
                confidence=0.0,
                matched_categories=[],
                reason="Empty input text",
                recommended_decision=SecurityDecision.ALLOW,
                matches=[]
            )

        matched_categories = set()
        matches = []
        max_confidence = 0.0

        # 1. Category Pattern Matching
        for pattern, category, confidence in self.CATEGORY_PATTERNS:
            found = re.findall(pattern, text)
            if found:
                matched_categories.add(category)
                max_confidence = max(max_confidence, confidence)
                matches.append({
                    "pattern": pattern,
                    "category": category.value,
                    "confidence": confidence,
                    "count": len(found)
                })

        # 2. Check for Base64 Obfuscation
        obfuscated_match = self._check_obfuscation(text)
        if obfuscated_match:
            matched_categories.add(InjectionCategory.OBFUSCATION)
            max_confidence = max(max_confidence, 0.85)
            matches.append(obfuscated_match)

        detected = len(matched_categories) > 0 and max_confidence >= self.high_threshold

        # 3. Trust-Aware Analysis (Contextual Risk Rating)
        is_false_positive_candidate = False
        is_trusted_source = (
            trust_level == TrustLevel.TRUSTED or
            source_category in [SourceCategory.SYSTEM, SourceCategory.DEVELOPER]
        )

        if is_trusted_source:
            # Trusted instructions are ALLOWED unless they contain metadata manipulation attacks
            if InjectionCategory.METADATA_MANIPULATION in matched_categories:
                risk_level = RiskLevel.HIGH
                recommended_decision = SecurityDecision.ISOLATE
                reason = "Metadata manipulation attempt detected in trusted instruction"
            else:
                is_false_positive_candidate = True
                risk_level = RiskLevel.LOW
                recommended_decision = SecurityDecision.ALLOW
                reason = "Instruction language expected from trusted source"
        else:
            # Untrusted, User-controlled, or Unknown sources
            if not detected:
                risk_level = RiskLevel.LOW
                recommended_decision = SecurityDecision.ALLOW
                reason = "No prompt injection patterns detected"
            else:
                if max_confidence >= self.critical_threshold or InjectionCategory.METADATA_MANIPULATION in matched_categories:
                    risk_level = RiskLevel.CRITICAL
                    recommended_decision = SecurityDecision.DENY if trust_level == TrustLevel.UNKNOWN else SecurityDecision.ISOLATE
                    reason = f"High-risk prompt injection detected: {', '.join([c.value for c in matched_categories])}"
                else:
                    risk_level = RiskLevel.HIGH
                    recommended_decision = SecurityDecision.ISOLATE
                    reason = f"Prompt injection threat detected: {', '.join([c.value for c in matched_categories])}"

        return PromptInjectionResult(
            detected=detected,
            risk_level=risk_level,
            confidence=round(max_confidence, 4),
            matched_categories=list(matched_categories),
            reason=reason,
            recommended_decision=recommended_decision,
            matches=matches,
            is_false_positive_candidate=is_false_positive_candidate
        )

    def _check_obfuscation(self, text: str) -> Optional[Dict[str, Any]]:
        """Scans for Base64 encoded strings containing injection directives."""
        # Find potential base64 blocks (min 16 chars)
        b64_blocks = re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text)
        for block in b64_blocks:
            try:
                decoded = base64.b64decode(block).decode("utf-8", errors="ignore")
                # Scan decoded string
                res = self.legacy_scanner.scan(decoded)
                if res["is_injection"]:
                    return {
                        "pattern": "base64_obfuscation",
                        "category": InjectionCategory.OBFUSCATION.value,
                        "confidence": 0.85,
                        "count": 1,
                        "decoded_sample": decoded[:50]
                    }
            except Exception:
                continue
        return None
