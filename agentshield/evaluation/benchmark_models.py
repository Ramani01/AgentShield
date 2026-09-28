"""
Security Benchmark Data Models for AgentShield Evaluation Corpus.
"""

import time
import uuid
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from agentshield.context.models import SecurityDecision
from agentshield.security.tool_models import ChangeSeverity
from agentshield.evaluation.models import (
    ControlStatus,
    SecurityControlResult,
    SecurityFinding,
    SecurityEvaluationContext
)
from agentshield.evaluation.catalog import ControlCatalog

class ScenarioType(str, Enum):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"
    REVIEW = "REVIEW"
    BOUNDARY = "BOUNDARY"
    REGRESSION = "REGRESSION"

class SecurityBenchmarkCase(BaseModel):
    """Structured, versioned evaluation case for systematically testing AgentShield controls."""

    case_id: str
    version: str = "1.0.0"
    title: str
    description: str
    category: str
    target_control_ids: List[str]
    scenario_type: ScenarioType = ScenarioType.POSITIVE
    input_fixture: SecurityEvaluationContext
    expected_status: ControlStatus
    expected_decision: SecurityDecision
    expected_findings: List[str] = Field(default_factory=list)
    severity: ChangeSeverity = ChangeSeverity.LOW
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True, "frozen": False}

class BenchmarkCorpus(BaseModel):
    """Versioned collection of SecurityBenchmarkCase definitions."""

    corpus_version: str = "1.0.0"
    created_at: float = Field(default_factory=time.time)
    description: str = "AgentShield Versioned Security Evaluation Corpus"
    cases: List[SecurityBenchmarkCase]
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True, "frozen": False}

    def validate_corpus(self) -> Dict[str, Any]:
        """
        Validates corpus definitions for uniqueness, control ID presence, and explicit expected results.
        Fails closed by returning valid=False if malformed cases exist.
        """
        seen_ids = set()
        errors = []
        valid_control_ids = {c.control_id for c in ControlCatalog.list_controls()}

        for case in self.cases:
            if not case.case_id or not case.case_id.strip():
                errors.append("Case missing case_id")
                continue
            if case.case_id in seen_ids:
                errors.append(f"Duplicate case_id found: '{case.case_id}'")
            seen_ids.add(case.case_id)

            if not case.target_control_ids:
                errors.append(f"Case '{case.case_id}' missing target_control_ids")
            else:
                for cid in case.target_control_ids:
                    if cid not in valid_control_ids:
                        errors.append(f"Case '{case.case_id}' references invalid control_id '{cid}'")

            if not case.expected_status:
                errors.append(f"Case '{case.case_id}' missing expected_status")
            if not case.expected_decision:
                errors.append(f"Case '{case.case_id}' missing expected_decision")

        return {"valid": len(errors) == 0, "errors": errors, "total_cases": len(self.cases)}

class BenchmarkCaseResult(BaseModel):
    """Result of running a single SecurityBenchmarkCase through SecurityEvaluationEngine."""

    case_id: str
    expected_status: ControlStatus
    actual_status: ControlStatus
    expected_decision: SecurityDecision
    actual_decision: SecurityDecision
    passed: bool
    is_false_positive_candidate: bool = False
    is_false_negative_candidate: bool = False
    control_results: List[SecurityControlResult] = Field(default_factory=list)
    findings: List[SecurityFinding] = Field(default_factory=list)
    discrepancy: Optional[str] = None
    duration_ms: float = 0.0

class SecurityBenchmarkReport(BaseModel):
    """Aggregate report summarizing the execution of a BenchmarkCorpus."""

    corpus_version: str
    started_at: float
    completed_at: float
    total_cases: int
    passed_cases: int
    failed_cases: int
    pass_rate: float
    false_positive_candidates: int = 0
    false_negative_candidates: int = 0
    control_summary: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    category_summary: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    duration_ms: float = 0.0
    failed_case_ids: List[str] = Field(default_factory=list)
