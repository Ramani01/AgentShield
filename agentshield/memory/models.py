"""
Memory Security Data Models for AgentShield.
"""

import time
import uuid
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

from agentshield.context.models import (
    SourceCategory,
    TrustLevel,
    SecurityDecision,
    InstructionType,
    UserIdentity,
    IntegrityStatus
)
from agentshield.provenance.models import compute_content_hash

class MemoryRecord(BaseModel):
    """Represents a security-annotated memory record in AgentShield."""

    memory_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    owner_id: str
    tenant_id: str
    content: str
    source_category: SourceCategory = SourceCategory.MEMORY
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    provenance_id: Optional[str] = None
    content_hash: str = ""
    created_at: float = Field(default_factory=time.time)
    expires_at: Optional[float] = None
    is_stale: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if not self.content_hash and self.content:
            self.content_hash = compute_content_hash(self.content)

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Checks if memory record has passed its expiration timestamp."""
        now = current_time if current_time is not None else time.time()
        if self.expires_at is not None and now > self.expires_at:
            return True
        return False

class MemoryAccessResult(BaseModel):
    """Result returned by MemorySecurityEngine after evaluating memory access."""

    memory_id: Optional[str] = None
    authorized: bool = False
    integrity_valid: bool = True
    provenance_valid: bool = True
    security_decision: SecurityDecision = SecurityDecision.DENY
    reason: str = ""
    context_item: Optional[Any] = None  # Holds ContextItem if authorized
    violations: List[str] = Field(default_factory=list)

class MemoryWriteRequest(BaseModel):
    """Represents a candidate request to persist information into agent memory."""

    user_id: str
    tenant_id: str
    content: str
    source_category: SourceCategory = SourceCategory.MEMORY
    provenance_id: Optional[str] = None
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    metadata: Dict[str, Any] = Field(default_factory=dict)
    requested_by: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)
    expires_at: Optional[float] = None
    memory_type: str = "general"
    key: Optional[str] = None

class MemoryWriteResult(BaseModel):
    """Represents the security evaluation result of a memory write operation."""

    allowed: bool = False
    decision: SecurityDecision = SecurityDecision.DENY
    reason: str = ""
    violations: List[str] = Field(default_factory=list)
    memory_id: Optional[str] = None
    provenance_id: Optional[str] = None
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    content_hash: str = ""
    integrity_valid: bool = True
    record: Optional[MemoryRecord] = None
