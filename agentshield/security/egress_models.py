"""
Egress Control Data Models for AgentShield.
"""

import time
import uuid
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from agentshield.context.models import SecurityDecision, TrustLevel, SourceCategory, UserIdentity
from agentshield.provenance.models import compute_content_hash

class DestinationCategory(str, Enum):
    INTERNAL = "INTERNAL"
    SAME_TENANT = "SAME_TENANT"
    SAME_USER = "SAME_USER"
    APPROVED_EXTERNAL = "APPROVED_EXTERNAL"
    UNKNOWN_EXTERNAL = "UNKNOWN_EXTERNAL"
    BLOCKED = "BLOCKED"

class EgressRequest(BaseModel):
    """Represents a request to export data across the AgentShield security boundary."""

    egress_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    tenant_id: str
    agent_id: str = "default_agent"
    data: str
    data_type: str = "text"
    destination: str
    destination_category: DestinationCategory = DestinationCategory.UNKNOWN_EXTERNAL
    purpose: Optional[str] = None
    provenance_id: Optional[str] = None
    parent_provenance_ids: List[str] = Field(default_factory=list)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    content_hash: str = ""
    item_count: int = 1
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)

    def model_post_init(self, __context: Any) -> None:
        if not self.content_hash and self.data:
            self.content_hash = compute_content_hash(self.data)

class EgressValidationResult(BaseModel):
    """Result of egress security evaluation."""

    egress_id: Optional[str] = None
    allowed: bool = False
    decision: SecurityDecision = SecurityDecision.DENY
    reason: str = ""
    violations: List[str] = Field(default_factory=list)
    sensitive_data_detected: bool = False
    destination_allowed: bool = False
    authorization_valid: bool = True
    provenance_valid: bool = True
    integrity_valid: bool = True
    trust_valid: bool = True
    is_high_risk: bool = False
    validation_time_ms: float = 0.0
    timestamp: float = Field(default_factory=time.time)
