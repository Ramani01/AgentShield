"""
Phase 29 Containment Benchmark Execution Script (7 scenarios x 100 iterations = 700 evaluations).
"""

import time
from agentshield import AgentShield
from agentshield.benchmark import (
    BenchmarkRunner,
    BenchmarkReporter,
    BenchmarkScenarioRegistry
)


def run_benchmark(iterations: int = 100, warmup_iterations: int = 5):
    shield = AgentShield()
    runner = shield.benchmark_runner
    registry = BenchmarkScenarioRegistry()
    scenarios = registry.list_scenarios()

    print(f"=== Phase 29 Containment Security Benchmark ===")
    print(f"Scenarios:           {len(scenarios)}")
    print(f"Warmup Iterations:   {warmup_iterations}")
    print(f"Measured Iterations: {iterations}")
    print(f"Total Evaluations:   {len(scenarios) * iterations}\n")

    t0 = time.perf_counter()
    results = runner.run_benchmark(
        iterations=iterations,
        warmup_iterations=warmup_iterations,
        tenant_id="bench_tenant",
        agent_id="bench_agent"
    )
    t1 = time.perf_counter()
    total_time_seconds = t1 - t0

    report = BenchmarkReporter.generate_report(
        "bench_tenant",
        "bench_agent",
        results,
        total_time_seconds=total_time_seconds
    )

    print(BenchmarkReporter.format_markdown_report(report))


if __name__ == "__main__":
    run_benchmark(iterations=100, warmup_iterations=5)
