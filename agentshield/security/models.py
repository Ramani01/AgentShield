"""
Security Threat and Detection Data Models for AgentShield.
"""

import time
import uuid
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from agentshield.context.models import TrustLevel, SourceCategory, SecurityDecision

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class InjectionCategory(str, Enum):
    INSTRUCTION_OVERRIDE = "Instruction Override Attempt"
    SYSTEM_IMPERSONATION = "System/Developer Impersonation"
    PRIORITY_MANIPULATION = "Instruction-Priority Manipulation"
    PROMPT_EXTRACTION = "Prompt Extraction/Reveal Attempt"
    BOUNDARY_BYPASS = "Security/Policy Boundary Bypass"
    METADATA_MANIPULATION = "Trust Metadata Manipulation"
    STATE_TAMPERING = "Memory/Security State Tampering"
    TOOL_INJECTION = "Tool/Action Instruction Injection"
    OBFUSCATION = "Encoded or Obfuscated Payload"

class PromptInjectionResult(BaseModel):
    """Structured result from trust-aware prompt injection detection."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detected: bool
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    matched_categories: List[InjectionCategory] = Field(default_factory=list)
    reason: str
    recommended_decision: SecurityDecision
    matches: List[Dict[str, Any]] = Field(default_factory=list)
    is_false_positive_candidate: bool = False
    timestamp: float = Field(default_factory=time.time)

    model_config = {"frozen": False}
