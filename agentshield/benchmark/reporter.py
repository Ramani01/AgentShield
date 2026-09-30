"""
Phase 29: Benchmark Report Generator.
Generates auditable, human-readable markdown benchmark reports.
"""

import time
from typing import List, Dict, Any, Optional
from agentshield.benchmark.models import (
    BenchmarkResult,
    BenchmarkMetrics,
    BenchmarkReport
)
from agentshield.benchmark.metrics import MetricsCalculator
from agentshield.benchmark.evaluator import BenchmarkEvaluator


class BenchmarkReporter:
    """
    Generates auditable markdown benchmark reports summarizing correctness, latencies, and security invariants.
    """

    @staticmethod
    def generate_report(
        tenant_id: str,
        agent_id: str,
        results: List[BenchmarkResult],
        total_time_seconds: Optional[float] = None,
        evaluator: Optional[BenchmarkEvaluator] = None
    ) -> BenchmarkReport:
        """Generates a complete BenchmarkReport with statistical metrics and invariant results."""
        metrics = MetricsCalculator.calculate_metrics(results, total_time_seconds=total_time_seconds)

        eval_inst = evaluator or BenchmarkEvaluator()
        invariant_results = eval_inst.verify_security_invariants(results, tenant_id=tenant_id, agent_id=agent_id)

        all_invariants_pass = all(invariant_results.values()) if invariant_results else True
        all_evals_pass = (metrics.failed_count == 0 and metrics.total_evaluations > 0)

        summary = {
            "all_evaluations_passed": all_evals_pass,
            "all_invariants_passed": all_invariants_pass,
            "overall_status": "PASS" if (all_evals_pass and all_invariants_pass) else "FAIL"
        }

        return BenchmarkReport(
            tenant_id=tenant_id,
            agent_id=agent_id,
            generated_at=time.time(),
            metrics=metrics,
            scenario_metrics=metrics.scenario_metrics,
            invariant_results=invariant_results,
            summary=summary
        )

    @staticmethod
    def format_markdown_report(report: BenchmarkReport) -> str:
        """Renders BenchmarkReport object as a clean Markdown document."""
        m = report.metrics or BenchmarkMetrics()

        lines = []
        lines.append("# [AgentShield] Containment Benchmark Report")
        lines.append(f"**Tenant ID:** `{report.tenant_id}` | **Agent ID:** `{report.agent_id}` | **Generated At:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(report.generated_at))}")
        lines.append("")
        lines.append("## Overall Metrics")
        lines.append(f"- **Total Evaluations:** {m.total_evaluations}")
        lines.append(f"- **Passed:** {m.passed_count}")
        lines.append(f"- **Failed:** {m.failed_count}")
        lines.append(f"- **Pass Rate:** {m.pass_rate * 100.0:.2f}%")
        lines.append(f"- **Average Latency:** {m.avg_latency_ms:.4f} ms")
        lines.append(f"- **Median Latency:** {m.median_latency_ms:.4f} ms")
        lines.append(f"- **P95 Latency:** {m.p95_latency_ms:.4f} ms")
        lines.append(f"- **P99 Latency:** {m.p99_latency_ms:.4f} ms")
        lines.append(f"- **Max Latency:** {m.max_latency_ms:.4f} ms")
        lines.append(f"- **Throughput:** {m.throughput_eps:.2f} evaluations/sec")
        lines.append("")
        lines.append("## Scenario Breakdown")
        lines.append("| Scenario ID | Runs | Passed | Failed | Pass Rate | Avg Latency (ms) | P95 (ms) | Max (ms) |")
        lines.append("|---|---|---|---|---|---|---|---|")

        for sid, sm in sorted(report.scenario_metrics.items()):
            pr = sm.get("pass_rate", 0.0) * 100.0
            lines.append(
                f"| `{sid}` | {sm.get('iterations', 0)} | {sm.get('passed_count', 0)} | {sm.get('failed_count', 0)} | "
                f"{pr:.1f}% | {sm.get('avg_latency_ms', 0.0):.4f} | {sm.get('p95_latency_ms', 0.0):.4f} | {sm.get('max_latency_ms', 0.0):.4f} |"
            )

        lines.append("")
        lines.append("## Security Invariants Verified")
        for inv_name, passed in report.invariant_results.items():
            status_str = "PASS" if passed else "FAIL"
            lines.append(f"- **{inv_name.replace('_', ' ').title()}:** [{status_str}]")

        lines.append("")
        lines.append(f"**Overall Benchmark Status:** `{report.summary.get('overall_status', 'UNKNOWN')}`")

        return "\n".join(lines)
