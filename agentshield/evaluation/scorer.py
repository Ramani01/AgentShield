"""
Security Scorer & Evaluation Metric Calculator.
"""

from typing import Dict, Any, List

class SecurityScorer:
    """Calculates security defense scores and resilience ratings."""

    @staticmethod
    def calculate_score(results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculates percentage pass rate and security index."""
        if not results:
            return {"pass_rate": 100.0, "total_tests": 0, "rating": "UNKNOWN"}

        total = len(results)
        passed = sum(1 for r in results if r.get("passed", False))
        pass_rate = (passed / total) * 100.0

        if pass_rate >= 90.0:
            rating = "SECURE (A+)"
        elif pass_rate >= 75.0:
            rating = "MODERATE (B)"
        else:
            rating = "VULNERABLE (F)"

        return {
            "pass_rate": round(pass_rate, 2),
            "passed": passed,
            "failed": total - passed,
            "total_tests": total,
            "rating": rating
        }
