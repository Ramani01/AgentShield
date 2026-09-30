"""
Security evaluation and benchmarking components.
"""

from agentshield.evaluation.harness import EvaluationHarness
from agentshield.evaluation.scorer import SecurityScorer
from agentshield.evaluation.benchmarks import PROMPT_INJECTION_SUITE, PII_LEAKAGE_SUITE
from agentshield.evaluation.models import (
    EvaluationScope,
    ControlCategory,
    ControlStatus,
    SecurityControlResult,
    SecurityFinding,
    SecurityEvaluationContext,
    SecurityEvaluation
)
from agentshield.evaluation.catalog import ControlDefinition, ControlCatalog
from agentshield.evaluation.evaluators import BaseSecurityEvaluator
from agentshield.evaluation.engine import SecurityEvaluationEngine

from agentshield.evaluation.benchmark_models import (
    ScenarioType,
    SecurityBenchmarkCase,
    BenchmarkCorpus,
    BenchmarkCaseResult,
    SecurityBenchmarkReport
)
from agentshield.evaluation.benchmark_cases import PRIMARY_BENCHMARK_CORPUS
from agentshield.evaluation.benchmark_runner import SecurityBenchmarkRunner

from agentshield.evaluation.containment_models import (
    EvaluationOutcome,
    EvaluationSeverity,
    SEVERITY_RANK,
    EvidenceRecord,
    ContainmentAssessment
)
from agentshield.evaluation.evidence import EvidenceNormalizer
from agentshield.evaluation.rules import EvaluationRule, RuleRegistry
from agentshield.evaluation.explain import DecisionExplainer
from agentshield.evaluation.containment_engine import ContainmentEvaluationEngine

__all__ = [
    "EvaluationHarness",
    "SecurityScorer",
    "PROMPT_INJECTION_SUITE",
    "PII_LEAKAGE_SUITE",
    "EvaluationScope",
    "ControlCategory",
    "ControlStatus",
    "SecurityControlResult",
    "SecurityFinding",
    "SecurityEvaluationContext",
    "SecurityEvaluation",
    "ControlDefinition",
    "ControlCatalog",
    "BaseSecurityEvaluator",
    "SecurityEvaluationEngine",
    "ScenarioType",
    "SecurityBenchmarkCase",
    "BenchmarkCorpus",
    "BenchmarkCaseResult",
    "SecurityBenchmarkReport",
    "PRIMARY_BENCHMARK_CORPUS",
    "SecurityBenchmarkRunner",
    "EvaluationOutcome",
    "EvaluationSeverity",
    "SEVERITY_RANK",
    "EvidenceRecord",
    "ContainmentAssessment",
    "EvidenceNormalizer",
    "EvaluationRule",
    "RuleRegistry",
    "DecisionExplainer",
    "ContainmentEvaluationEngine"
]


