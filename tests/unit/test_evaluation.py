"""
Unit tests for evaluation harness and security scorer.
"""

from agentshield.evaluation.harness import EvaluationHarness
from agentshield.evaluation.scorer import SecurityScorer

def test_security_scorer():
    sample_results = [
        {"passed": True},
        {"passed": True},
        {"passed": False}
    ]
    res = SecurityScorer.calculate_score(sample_results)
    assert res["passed"] == 2
    assert res["failed"] == 1
    assert res["pass_rate"] == 66.67
    assert res["rating"] == "VULNERABLE (F)"

def test_evaluation_harness_suite():
    harness = EvaluationHarness()
    suite_res = harness.run_injection_suite()

    assert "summary" in suite_res
    assert suite_res["summary"]["pass_rate"] >= 75.0
    assert len(suite_res["details"]) > 0
