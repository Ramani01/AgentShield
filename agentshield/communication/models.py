"""
Data models and principal representations for Phase 22 Agent Communication & Service Policy.
"""

from enum import Enum
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
import time
import uuid

from agentshield.context.models import UserIdentity, SecurityDecision


class PrincipalType(str, Enum):
    """Types of communication principals/services."""
    AGENT = "AGENT"
    INTERNAL_SERVICE = "INTERNAL_SERVICE"
    APPROVED_TOOL = "APPROVED_TOOL"
    SAME_TENANT_SERVICE = "SAME_TENANT_SERVICE"
    APPROVED_EXTERNAL = "APPROVED_EXTERNAL"
    UNKNOWN_SERVICE = "UNKNOWN_SERVICE"


class CommunicationType(str, Enum):
    """Explicit communication channel categories."""
    AGENT_TO_AGENT = "AGENT_TO_AGENT"
    AGENT_TO_SERVICE = "AGENT_TO_SERVICE"
    SERVICE_TO_AGENT = "SERVICE_TO_AGENT"
    AGENT_TO_TOOL = "AGENT_TO_TOOL"
    SERVICE_TO_SERVICE = "SERVICE_TO_SERVICE"


@dataclass
class CommunicationPrincipal:
    """Represents an agent, service, tool, or external principal participating in communication."""
    principal_id: str
    principal_type: PrincipalType
    name: str
    tenant_id: str = "default"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "principal_type": self.principal_type.value,
            "name": self.name,
            "tenant_id": self.tenant_id,
            "metadata": self.metadata,
        }


@dataclass
class CommunicationPolicyRule:
    """Defines an explicit policy rule governing communication between principals."""
    rule_id: str = field(default_factory=lambda: f"rule_{uuid.uuid4().hex[:8]}")
    source_principal_id: Optional[str] = None
    source_type: Optional[PrincipalType] = None
    destination_principal_id: Optional[str] = None
    destination_type: Optional[PrincipalType] = None
    comm_type: Optional[CommunicationType] = None
    tenant_relationship: str = "SAME_TENANT"  # "SAME_TENANT", "CROSS_TENANT", "ANY"
    allowed_data_classifications: Optional[List[str]] = None
    decision: SecurityDecision = SecurityDecision.ALLOW
    reason: str = "Policy rule matched"


@dataclass
class CommunicationRequest:
    """Request object representing a proposed communication between principals."""
    source: CommunicationPrincipal
    destination: CommunicationPrincipal
    comm_type: CommunicationType
    data_classification: str = "INTERNAL"
    identity: Optional[UserIdentity] = None
    context_data: Dict[str, Any] = field(default_factory=dict)
    audience_scope: Optional[str] = None
    egress_target: Optional[str] = None
    request_id: str = field(default_factory=lambda: f"creq_{uuid.uuid4().hex[:8]}")


@dataclass
class CommunicationDecisionResult:
    """Security decision result for a communication policy evaluation."""
    decision_id: str = field(default_factory=lambda: f"cdec_{uuid.uuid4().hex[:8]}")
    allowed: bool = False
    decision: SecurityDecision = SecurityDecision.DENY
    reason: str = ""
    matched_rule_id: Optional[str] = None
    violations: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "allowed": self.allowed,
            "decision": self.decision.value,
            "reason": self.reason,
            "matched_rule_id": self.matched_rule_id,
            "violations": self.violations,
            "timestamp": self.timestamp,
        }
