"""
Security Benchmark Runner for AgentShield Evaluation Corpus.

Loads corpus, validates case definitions, executes evaluation cases via SecurityEvaluationEngine,
compares actual vs expected decisions and control statuses, calculates coverage,
identifies candidate false positives / false negatives, and produces a SecurityBenchmarkReport.
"""

import time
from typing import Dict, Any, List, Optional
from agentshield.context.models import SecurityDecision
from agentshield.evaluation.models import ControlStatus, SecurityEvaluationContext
from agentshield.evaluation.engine import SecurityEvaluationEngine
from agentshield.evaluation.catalog import ControlCatalog
from agentshield.evaluation.benchmark_models import (
    SecurityBenchmarkCase,
    BenchmarkCorpus,
    BenchmarkCaseResult,
    SecurityBenchmarkReport
)

class SecurityBenchmarkRunner:
    """
    Executes SecurityBenchmarkCase definitions through SecurityEvaluationEngine.
    Validates corpus definitions, calculates pass/fail metrics, coverage, and candidate FP/FNs.
    """

    def __init__(
        self,
        engine: Optional[SecurityEvaluationEngine] = None,
        pipeline: Optional[Any] = None
    ):
        if pipeline is None:
            from agentshield.core.pipeline import SecurityPipeline
            self.pipeline = SecurityPipeline()
        else:
            self.pipeline = pipeline

        self.engine = engine or getattr(self.pipeline, "evaluation_engine", None) or SecurityEvaluationEngine()

    def run_case(self, case: SecurityBenchmarkCase) -> BenchmarkCaseResult:
        """
        Executes a single SecurityBenchmarkCase against SecurityEvaluationEngine.
        Does NOT bypass the evaluation engine or execute external tools/networks.
        """
        start_time = time.time()
        
        # Execute evaluation path using actual SecurityEvaluationEngine
        evaluation = self.engine.evaluate(case.input_fixture, self.pipeline)
        
        duration_ms = (time.time() - start_time) * 1000.0

        actual_status = evaluation.status
        actual_decision = evaluation.overall_decision

        # Explicit independent comparison
        status_match = (actual_status == case.expected_status)
        decision_match = (actual_decision == case.expected_decision)
        passed = status_match and decision_match

        discrepancy = None
        if not passed:
            discrepancy = (
                f"Expected status={case.expected_status.value}, decision={case.expected_decision.value}; "
                f"Got status={actual_status.value}, decision={actual_decision.value}"
            )

        # False positive candidate: AgentShield blocked/reviewed a scenario expected to be ALLOWED
        is_fp = (
            case.expected_decision == SecurityDecision.ALLOW and
            actual_decision in [SecurityDecision.DENY, SecurityDecision.REVIEW, SecurityDecision.ISOLATE]
        )

        # False negative candidate: AgentShield allowed a scenario expected to be BLOCKED/REVIEWED
        is_fn = (
            case.expected_decision in [SecurityDecision.DENY, SecurityDecision.REVIEW, SecurityDecision.ISOLATE] and
            actual_decision == SecurityDecision.ALLOW
        )

        return BenchmarkCaseResult(
            case_id=case.case_id,
            expected_status=case.expected_status,
            actual_status=actual_status,
            expected_decision=case.expected_decision,
            actual_decision=actual_decision,
            passed=passed,
            is_false_positive_candidate=is_fp,
            is_false_negative_candidate=is_fn,
            control_results=evaluation.control_results,
            findings=evaluation.findings,
            discrepancy=discrepancy,
            duration_ms=duration_ms
        )

    def run_corpus(self, corpus: BenchmarkCorpus) -> SecurityBenchmarkReport:
        """
        Validates and runs an entire BenchmarkCorpus, producing a structured SecurityBenchmarkReport.
        Fails closed if corpus definition is malformed.
        """
        # Step 1: Validate corpus definitions
        val_result = corpus.validate_corpus()
        if not val_result["valid"]:
            err_msg = "; ".join(val_result["errors"])
            raise ValueError(f"Corpus validation failed (fail-closed): {err_msg}")

        started_at = time.time()

        results: List[BenchmarkCaseResult] = []
        failed_case_ids: List[str] = []
        passed_count = 0
        failed_count = 0
        fp_count = 0
        fn_count = 0

        # Pre-populate control summary map
        control_summary: Dict[str, Dict[str, Any]] = {}
        for c_def in ControlCatalog.list_controls():
            control_summary[c_def.control_id] = {
                "control_id": c_def.control_id,
                "name": c_def.name,
                "total_cases": 0,
                "passed_cases": 0,
                "failed_cases": 0,
                "coverage_status": "NO_COVERAGE"
            }

        # Pre-populate category summary map
        category_summary: Dict[str, Dict[str, Any]] = {}

        # Step 2: Execute benchmark cases
        for case in corpus.cases:
            res = self.run_case(case)
            results.append(res)

            if res.passed:
                passed_count += 1
            else:
                failed_count += 1
                failed_case_ids.append(case.case_id)

            if res.is_false_positive_candidate:
                fp_count += 1
            if res.is_false_negative_candidate:
                fn_count += 1

            # Update control-level metrics
            for cid in case.target_control_ids:
                if cid in control_summary:
                    control_summary[cid]["total_cases"] += 1
                    if res.passed:
                        control_summary[cid]["passed_cases"] += 1
                    else:
                        control_summary[cid]["failed_cases"] += 1
                    control_summary[cid]["coverage_status"] = "COVERED"

            # Update category-level metrics
            cat_name = case.category
            if cat_name not in category_summary:
                category_summary[cat_name] = {
                    "category_name": cat_name,
                    "total_cases": 0,
                    "passed_cases": 0,
                    "failed_cases": 0,
                    "coverage_status": "COVERED"
                }
            category_summary[cat_name]["total_cases"] += 1
            if res.passed:
                category_summary[cat_name]["passed_cases"] += 1
            else:
                category_summary[cat_name]["failed_cases"] += 1

        completed_at = time.time()
        total_cases = len(corpus.cases)
        pass_rate = (passed_count / total_cases * 100.0) if total_cases > 0 else 0.0
        total_duration_ms = (completed_at - started_at) * 1000.0

        return SecurityBenchmarkReport(
            corpus_version=corpus.corpus_version,
            started_at=started_at,
            completed_at=completed_at,
            total_cases=total_cases,
            passed_cases=passed_count,
            failed_cases=failed_count,
            pass_rate=pass_rate,
            false_positive_candidates=fp_count,
            false_negative_candidates=fn_count,
            control_summary=control_summary,
            category_summary=category_summary,
            duration_ms=total_duration_ms,
            failed_case_ids=failed_case_ids
        )
