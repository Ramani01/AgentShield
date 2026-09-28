"""
Context, Instruction, Trust, and Integrity Data Models for AgentShield.
"""

import time
import uuid
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class InstructionType(str, Enum):
    SYSTEM = "SYSTEM"
    DEVELOPER = "DEVELOPER"
    USER = "USER"
    MEMORY = "MEMORY"
    RETRIEVED_CONTENT = "RETRIEVED_CONTENT"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    EXTERNAL_CONTENT = "EXTERNAL_CONTENT"

class SourceCategory(str, Enum):
    SYSTEM = "SYSTEM"
    DEVELOPER = "DEVELOPER"
    USER = "USER"
    INTERNAL_DATABASE = "INTERNAL_DATABASE"
    VERIFIED_DOCUMENT = "VERIFIED_DOCUMENT"
    MEMORY = "MEMORY"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    WEB_CONTENT = "WEB_CONTENT"
    EXTERNAL_DOCUMENT = "EXTERNAL_DOCUMENT"
    UNKNOWN = "UNKNOWN"

class TrustLevel(str, Enum):
    TRUSTED = "TRUSTED"
    INTERNAL = "INTERNAL"
    USER_CONTROLLED = "USER_CONTROLLED"
    UNTRUSTED = "UNTRUSTED"
    UNKNOWN = "UNKNOWN"

class SecurityDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ISOLATE = "ISOLATE"
    REVIEW = "REVIEW"

class IntegrityStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    REVIEW = "REVIEW"

INSTRUCTION_PRIORITIES: Dict[InstructionType, int] = {
    InstructionType.SYSTEM: 100,
    InstructionType.DEVELOPER: 90,
    InstructionType.MEMORY: 70,
    InstructionType.USER: 50,
    InstructionType.TOOL_OUTPUT: 30,
    InstructionType.RETRIEVED_CONTENT: 20,
    InstructionType.EXTERNAL_CONTENT: 10,
}

class TrustLabel(BaseModel):
    """Represents authoritative trust metadata assigned to a content source."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_category: SourceCategory
    trust_level: TrustLevel
    classifier_id: str = "AgentShield.TrustClassifier.v1"
    reason: str = "Classified based on explicit source category policy"
    provenance_id: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)
    is_instruction_allowed: bool = False
    decision: SecurityDecision = SecurityDecision.ALLOW
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": False}

class UserIdentity(BaseModel):
    """Represents an authenticated principal requesting agent operations."""

    user_id: str
    roles: List[str] = Field(default_factory=lambda: ["user"])
    tenant_id: str = "default"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": False}

class ContextItem(BaseModel):
    """Represents a single contextual item with strict trust and origin metadata."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    content: str
    raw_content: str
    instruction_type: InstructionType
    source_category: SourceCategory = SourceCategory.UNKNOWN
    trust_level: TrustLevel
    trust_label: Optional[TrustLabel] = None
    origin: str
    provenance_id: Optional[str] = None
    content_hash: Optional[str] = None
    is_instruction_allowed: bool = False
    priority: int = 0
    decision: SecurityDecision = SecurityDecision.ALLOW
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": False}

class ContextIntegrityResult(BaseModel):
    """Structured result from ContextIntegrityEngine validation."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    valid: bool
    integrity_status: IntegrityStatus
    violations: List[str] = Field(default_factory=list)
    provenance_valid: bool = True
    hash_valid: bool = True
    trust_valid: bool = True
    instruction_boundary_valid: bool = True
    security_decision: SecurityDecision = SecurityDecision.ALLOW
    reason: str = "Context integrity verified"
    validation_time_ms: float = 0.0
    item_count: int = 0
    timestamp: float = Field(default_factory=time.time)

    model_config = {"frozen": False}
