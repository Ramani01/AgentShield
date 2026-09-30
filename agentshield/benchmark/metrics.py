"""
Phase 29: Benchmark Metrics Calculator.
Calculates correctness, latency distributions (min, max, avg, median, P95, P99), and throughput.
"""

from typing import List, Dict, Any, Optional
from agentshield.benchmark.models import BenchmarkResult, BenchmarkMetrics


def _percentile(values: List[float], p: float) -> float:
    """Calculates percentile p (0-100) using linear interpolation."""
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]

    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = f + 1
    if c >= len(sorted_vals):
        return sorted_vals[-1]
    d = k - f
    return sorted_vals[f] + d * (sorted_vals[c] - sorted_vals[f])


class MetricsCalculator:
    """
    Calculates statistical metrics over benchmark evaluation results.
    """

    @staticmethod
    def calculate_metrics(
        results: List[BenchmarkResult],
        total_time_seconds: Optional[float] = None
    ) -> BenchmarkMetrics:
        """Computes comprehensive correctness, latency, and throughput metrics."""
        if not results:
            return BenchmarkMetrics()

        total = len(results)
        passed = sum(1 for r in results if r.pass_status)
        failed = total - passed
        pass_rate = (passed / total) if total > 0 else 0.0

        latencies = [r.latency_ms for r in results]
        min_lat = min(latencies) if latencies else 0.0
        max_lat = max(latencies) if latencies else 0.0
        avg_lat = (sum(latencies) / total) if total > 0 else 0.0
        median_lat = _percentile(latencies, 50.0)
        p95_lat = _percentile(latencies, 95.0)
        p99_lat = _percentile(latencies, 99.0)

        tot_time = total_time_seconds if total_time_seconds is not None else (sum(latencies) / 1000.0)
        throughput = (total / tot_time) if tot_time > 0 else 0.0

        # Scenario-level metric grouping
        scenario_grouped: Dict[str, List[BenchmarkResult]] = {}
        for r in results:
            scenario_grouped.setdefault(r.scenario_id, []).append(r)

        scenario_metrics: Dict[str, Dict[str, Any]] = {}
        for sid, s_results in scenario_grouped.items():
            s_total = len(s_results)
            s_passed = sum(1 for r in s_results if r.pass_status)
            s_failed = s_total - s_passed
            s_pass_rate = (s_passed / s_total) if s_total > 0 else 0.0

            s_lats = [r.latency_ms for r in s_results]
            scenario_metrics[sid] = {
                "scenario_id": sid,
                "iterations": s_total,
                "passed_count": s_passed,
                "failed_count": s_failed,
                "pass_rate": round(s_pass_rate, 4),
                "min_latency_ms": round(min(s_lats), 4) if s_lats else 0.0,
                "max_latency_ms": round(max(s_lats), 4) if s_lats else 0.0,
                "avg_latency_ms": round(sum(s_lats) / s_total, 4) if s_total > 0 else 0.0,
                "median_latency_ms": round(_percentile(s_lats, 50.0), 4),
                "p95_latency_ms": round(_percentile(s_lats, 95.0), 4)
            }

        return BenchmarkMetrics(
            total_evaluations=total,
            passed_count=passed,
            failed_count=failed,
            pass_rate=round(pass_rate, 4),
            mismatch_count=failed,
            min_latency_ms=round(min_lat, 4),
            max_latency_ms=round(max_lat, 4),
            avg_latency_ms=round(avg_lat, 4),
            median_latency_ms=round(median_lat, 4),
            p95_latency_ms=round(p95_lat, 4),
            p99_latency_ms=round(p99_lat, 4),
            throughput_eps=round(throughput, 2),
            total_time_seconds=round(tot_time, 4),
            scenario_metrics=scenario_metrics
        )
