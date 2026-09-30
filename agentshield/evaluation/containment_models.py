"""
Phase 27: Containment Evaluation Engine Models.
"""

import time
import uuid
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional


class EvaluationOutcome:
    """Explicit containment evaluation outcome recommendations."""
    NO_ACTION = "NO_ACTION"
    REVIEW = "REVIEW"
    MAINTAIN = "MAINTAIN"
    ESCALATE = "ESCALATE"
    RELEASE_REVIEW = "RELEASE_REVIEW"

    @classmethod
    def all_outcomes(cls) -> List[str]:
        return [cls.NO_ACTION, cls.REVIEW, cls.MAINTAIN, cls.ESCALATE, cls.RELEASE_REVIEW]


class EvaluationSeverity:
    """Explicit severity levels for security evaluation."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def all_severities(cls) -> List[str]:
        return [cls.LOW, cls.MEDIUM, cls.HIGH, cls.CRITICAL]


# Severity rank map for deterministic comparison
SEVERITY_RANK: Dict[str, int] = {
    EvaluationSeverity.LOW: 1,
    EvaluationSeverity.MEDIUM: 2,
    EvaluationSeverity.HIGH: 3,
    EvaluationSeverity.CRITICAL: 4
}


@dataclass
class EvidenceRecord:
    """Normalized security evidence record collected from security phases 1-26."""
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_phase: str = "Phase-24"
    source_control: str = "SECURITY_EVALUATOR"
    evidence_type: str = "BEHAVIOR_PATTERN"
    severity: str = EvaluationSeverity.LOW
    confidence: float = 1.0
    tenant_id: str = "default"
    agent_id: str = "default"
    timestamp: float = field(default_factory=time.time)
    freshness_status: str = "CURRENT"  # CURRENT, STALE, EXPIRED
    references: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.evidence_id:
            self.evidence_id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = time.time()
        if not self.tenant_id:
            self.tenant_id = "default"
        if not self.agent_id:
            self.agent_id = "default"

    def compute_evidence_hash(self) -> str:
        """Computes a deterministic SHA-256 fingerprint of the normalized evidence."""
        payload = {
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "source_phase": self.source_phase,
            "source_control": self.source_control,
            "evidence_type": self.evidence_type,
            "severity": self.severity,
            "references": self.references,
            "metadata": self.metadata
        }
        raw = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["evidence_hash"] = self.compute_evidence_hash()
        return res


@dataclass
class ContainmentAssessment:
    """Deterministic containment evaluation assessment result."""
    assessment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default"
    agent_id: str = "default"
    outcome: str = EvaluationOutcome.NO_ACTION
    severity: str = EvaluationSeverity.LOW
    confidence: float = 1.0
    matched_rules: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    current_containment_state: Optional[str] = None
    recommended_isolation_level: str = "NONE"
    explanation: str = ""
    created_at: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.assessment_id:
            self.assessment_id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
