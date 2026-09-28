"""
Tool Security and Change Governance Data Models for AgentShield.
"""

import time
import uuid
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from agentshield.context.models import SecurityDecision, TrustLevel, SourceCategory

class ChangeSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ToolDefinition(BaseModel):
    """Represents a declared tool interface, schemas, capabilities, and security metadata."""

    tool_id: str
    name: str
    version: str = "1.0.0"
    description: str = ""
    input_schema: Dict[str, Any] = Field(default_factory=dict)
    output_schema: Dict[str, Any] = Field(default_factory=dict)
    capabilities: List[str] = Field(default_factory=list)
    security_metadata: Dict[str, Any] = Field(default_factory=dict)
    provenance_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ToolBaseline(BaseModel):
    """Represents a previously approved/observed tool definition baseline."""

    tool_id: str
    fingerprint: str
    version: str = "1.0.0"
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    provenance_id: Optional[str] = None
    definition: Optional[ToolDefinition] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ToolChangeResult(BaseModel):
    """Result of tool definition change detection and governance evaluation."""

    changed: bool = False
    tool_id: str
    old_fingerprint: Optional[str] = None
    new_fingerprint: str
    changed_fields: List[str] = Field(default_factory=list)
    decision: SecurityDecision = SecurityDecision.ALLOW
    severity: ChangeSeverity = ChangeSeverity.LOW
    reason: str = ""
    detected_at: float = Field(default_factory=time.time)
    provenance_id: Optional[str] = None
