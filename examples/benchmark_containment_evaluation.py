"""
Phase 27 Containment Evaluation Engine Synthetic Benchmark.
"""

import time
from agentshield.evaluation import ContainmentEvaluationEngine, EvidenceRecord, EvaluationSeverity


def run_benchmark(iterations: int = 1000):
    engine = ContainmentEvaluationEngine()

    ev1 = EvidenceRecord(
        source_phase="Phase-23",
        evidence_type="RUNTIME_INTEGRITY",
        severity=EvaluationSeverity.LOW,
        tenant_id="bench_t",
        agent_id="bench_a",
        references={"integrity_state": "VALID"}
    )
    ev2 = EvidenceRecord(
        source_phase="Phase-24",
        evidence_type="BEHAVIOR_PATTERN",
        severity=EvaluationSeverity.CRITICAL,
        tenant_id="bench_t",
        agent_id="bench_a",
        references={"pattern_id": "BEHAVIOR-001"}
    )
    ev3 = EvidenceRecord(
        source_phase="Phase-26",
        evidence_type="SECURITY_GRAPH_PATH",
        severity=EvaluationSeverity.HIGH,
        tenant_id="bench_t",
        agent_id="bench_a",
        references={"signals": ["UNAUTHORIZED_TARGET"]}
    )

    evidence_records = [ev1, ev2, ev3]

    start_time = time.perf_counter()
    latencies = []

    for _ in range(iterations):
        t0 = time.perf_counter()
        engine.evaluate_evidence("bench_t", "bench_a", evidence_records)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)  # ms

    total_time = time.perf_counter() - start_time
    avg_latency = sum(latencies) / len(latencies)
    max_latency = max(latencies)
    throughput = iterations / total_time

    print(f"=== Phase 27 Evaluation Engine Benchmark ===")
    print(f"Iterations:                 {iterations}")
    print(f"Evidence Records per Cycle: {len(evidence_records)}")
    print(f"Total Time:                 {total_time:.4f} s")
    print(f"Average Latency:            {avg_latency:.4f} ms")
    print(f"Max Latency:                {max_latency:.4f} ms")
    print(f"Throughput:                 {throughput:.2f} eval/sec")


if __name__ == "__main__":
    run_benchmark(1000)
