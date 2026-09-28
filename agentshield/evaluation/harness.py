"""
Evaluation Harness for running security benchmarks against target functions/agents.
"""

from typing import Dict, Any, Callable, List
from agentshield.evaluation.benchmarks import PROMPT_INJECTION_SUITE
from agentshield.evaluation.scorer import SecurityScorer
from agentshield.security.injection import PromptInjectionScanner

class EvaluationHarness:
    """Automated benchmark harness for red-teaming AI agent pipelines."""

    def __init__(self, scanner: PromptInjectionScanner = None):
        self.scanner = scanner or PromptInjectionScanner()

    def run_injection_suite(self) -> Dict[str, Any]:
        """Runs prompt injection benchmark suite and reports security scores."""
        test_results = []

        for test in PROMPT_INJECTION_SUITE:
            scan_res = self.scanner.scan(test["prompt"])
            blocked = scan_res["is_injection"]
            expected = test["expected_blocked"]

            passed = (blocked == expected)
            test_results.append({
                "id": test["id"],
                "category": test["category"],
                "passed": passed,
                "detected": blocked,
                "expected": expected
            })

        score_summary = SecurityScorer.calculate_score(test_results)
        return {
            "summary": score_summary,
            "details": test_results
        }
