"""
Token / Data Audience Data Models for AgentShield.
"""

import time
import uuid
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from agentshield.context.models import SecurityDecision, TrustLevel, SourceCategory, UserIdentity

class AudienceType(str, Enum):
    SAME_USER = "SAME_USER"
    SAME_TENANT = "SAME_TENANT"
    INTERNAL = "INTERNAL"
    SPECIFIC_PRINCIPAL = "SPECIFIC_PRINCIPAL"
    APPROVED_SERVICE = "APPROVED_SERVICE"
    APPROVED_EXTERNAL = "APPROVED_EXTERNAL"
    PUBLIC = "PUBLIC"
    UNKNOWN = "UNKNOWN"

class AudienceClaim(BaseModel):
    """Represents the intended/permitted audience claim bound to a data item."""

    audience_type: AudienceType = AudienceType.UNKNOWN
    principal_id: Optional[str] = None
    tenant_id: Optional[str] = None
    issued_by: Optional[str] = "AgentShield.AudienceManager"
    provenance_id: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class AudiencePolicy(BaseModel):
    """Deterministic policy governing audience disclosure limits."""

    allowed_audience_types: List[AudienceType] = Field(
        default_factory=lambda: [
            AudienceType.SAME_USER,
            AudienceType.SAME_TENANT,
            AudienceType.INTERNAL,
            AudienceType.SPECIFIC_PRINCIPAL,
            AudienceType.APPROVED_SERVICE,
            AudienceType.APPROVED_EXTERNAL,
        ]
    )
    allowed_principals: List[str] = Field(default_factory=list)
    allowed_tenants: List[str] = Field(default_factory=list)
    allow_public: bool = False
    require_explicit_audience: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SecurityTokenContext(BaseModel):
    """Local security representation of token audience metadata (non-cryptographic local evaluation model)."""

    token_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    subject_id: str
    tenant_id: str
    audience: AudienceType = AudienceType.SAME_USER
    scopes: List[str] = Field(default_factory=list)
    issued_at: float = Field(default_factory=time.time)
    expires_at: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Checks if security token context has expired."""
        now = current_time if current_time is not None else time.time()
        if self.expires_at is not None and now > self.expires_at:
            return True
        return False

class AudienceValidationResult(BaseModel):
    """Result of audience authorization evaluation."""

    valid: bool = False
    decision: SecurityDecision = SecurityDecision.DENY
    reason: str = ""
    violations: List[str] = Field(default_factory=list)
    audience_type: AudienceType = AudienceType.UNKNOWN
    principal_valid: bool = True
    tenant_valid: bool = True
    token_valid: bool = True
    validation_time_ms: float = 0.0
    timestamp: float = Field(default_factory=time.time)
