"""
Security Evaluation Data Models for AgentShield.
"""

import time
import uuid
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from agentshield.context.models import SecurityDecision, UserIdentity, ContextItem
from agentshield.security.tool_models import ChangeSeverity, ToolDefinition
from agentshield.memory.models import MemoryRecord, MemoryWriteRequest
from agentshield.security.output_action_models import AgentOutput, AgentAction
from agentshield.security.egress_models import EgressRequest
from agentshield.security.audience_models import AudienceClaim
from agentshield.provenance.lineage import ProvenanceTracker

class EvaluationScope(str, Enum):
    FULL = "FULL"
    CONTEXT = "CONTEXT"
    MEMORY = "MEMORY"
    TOOLS = "TOOLS"
    OUTPUT = "OUTPUT"
    EGRESS = "EGRESS"
    CHECKPOINT = "CHECKPOINT"
    RETRIEVED = "RETRIEVED"

class ControlCategory(str, Enum):
    CONTEXT = "CONTEXT"
    TRUST = "TRUST"
    INJECTION = "INJECTION"
    PROVENANCE = "PROVENANCE"
    RETRIEVED = "RETRIEVED"
    INTEGRITY = "INTEGRITY"
    MEMORY = "MEMORY"
    MEMORY_WRITE = "MEMORY_WRITE"
    OUTPUT = "OUTPUT"
    EGRESS = "EGRESS"
    AUDIENCE = "AUDIENCE"
    GOVERNANCE = "GOVERNANCE"
    CHECKPOINT = "CHECKPOINT"

class ControlStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"
    NOT_EVALUATED = "NOT_EVALUATED"
    ERROR = "ERROR"

class SecurityControlResult(BaseModel):
    """Result of evaluating a single AgentShield security control."""

    control_id: str
    control_name: str
    category: ControlCategory
    status: ControlStatus = ControlStatus.NOT_EVALUATED
    decision: SecurityDecision = SecurityDecision.ALLOW
    severity: ChangeSeverity = ChangeSeverity.LOW
    reason: str = ""
    evidence: Dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)

class SecurityFinding(BaseModel):
    """Represents a specific defensive security finding identified during evaluation."""

    finding_id: str = Field(default_factory=lambda: f"fnd_{uuid.uuid4().hex[:12]}")
    control_id: str
    severity: ChangeSeverity
    title: str
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    recommendation: str = ""
    decision: SecurityDecision = SecurityDecision.REVIEW

class SecurityEvaluationContext(BaseModel):
    """Input context passed into SecurityEvaluationEngine for security assessment."""

    identity: Optional[UserIdentity] = None
    tenant_id: str = "default"
    context_items: List[ContextItem] = Field(default_factory=list)
    retrieval_request: Optional[Dict[str, Any]] = None
    retrieval_records: List[Dict[str, Any]] = Field(default_factory=list)
    memory_records: List[MemoryRecord] = Field(default_factory=list)
    memory_write_request: Optional[MemoryWriteRequest] = None
    agent_output: Optional[AgentOutput] = None
    agent_action: Optional[AgentAction] = None
    egress_request: Optional[EgressRequest] = None
    audience_claim: Optional[AudienceClaim] = None
    token_context: Optional[Any] = None
    tool_definitions: List[ToolDefinition] = Field(default_factory=list)
    expected_tool_id: Optional[str] = None
    checkpoint_id: Optional[str] = None
    provenance_tracker: Optional[ProvenanceTracker] = None
    scope: EvaluationScope = EvaluationScope.FULL
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True, "frozen": False}

class SecurityEvaluation(BaseModel):
    """Aggregate, evidence-based security assessment produced by SecurityEvaluationEngine."""

    evaluation_id: str = Field(default_factory=lambda: f"eval_{uuid.uuid4().hex[:12]}")
    evaluated_at: float = Field(default_factory=time.time)
    evaluator_id: str = "AgentShield.SecurityEvaluationEngine.v1"
    tenant_id: str = "default"
    scope: EvaluationScope = EvaluationScope.FULL
    status: ControlStatus = ControlStatus.REVIEW
    overall_decision: SecurityDecision = SecurityDecision.REVIEW
    findings: List[SecurityFinding] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    control_results: List[SecurityControlResult] = Field(default_factory=list)
    invariant_results: Dict[str, bool] = Field(default_factory=dict)
    summary: Dict[str, Any] = Field(default_factory=dict)
    evaluation_fingerprint: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True, "frozen": False}
