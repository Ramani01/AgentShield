"""
Synthetic Performance Benchmark for Phase 24 Multi-Step Behavioral Detection.
"""

import time
import sys
from typing import Dict, Any
from agentshield.behavior import BehaviorEngine, BehaviorEventType


def run_behavior_performance_benchmark(
    num_agents: int = 10,
    events_per_agent: int = 50,
    num_patterns: int = 5
) -> Dict[str, Any]:
    engine = BehaviorEngine()
    total_events = num_agents * events_per_agent

    latencies = []
    patterns_evaluated_total = 0

    event_cycle = [
        BehaviorEventType.READ_DOCUMENT,
        BehaviorEventType.READ_MEMORY,
        BehaviorEventType.USE_TOOL,
        BehaviorEventType.MODIFY_CONFIGURATION,
        BehaviorEventType.EXTERNAL_COMMUNICATION,
        BehaviorEventType.DATA_EXPORT,
    ]

    start_time = time.perf_counter()

    for a_idx in range(num_agents):
        agent_id = f"bench_agent_{a_idx}"
        for e_idx in range(events_per_agent):
            event_type = event_cycle[e_idx % len(event_cycle)]

            t0 = time.perf_counter()
            assessment = engine.record_event(
                event_type=event_type,
                tenant_id="bench_tenant",
                agent_id=agent_id,
                metadata={"seq_index": e_idx}
            )
            t1 = time.perf_counter()

            latencies.append((t1 - t0) * 1000.0)  # ms
            patterns_evaluated_total += len(engine.pattern_registry.list_patterns())

    total_time = time.perf_counter() - start_time

    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    max_latency = max(latencies) if latencies else 0.0

    return {
        "num_agents": num_agents,
        "events_per_agent": events_per_agent,
        "total_events": total_events,
        "sequence_length": events_per_agent,
        "num_patterns": num_patterns,
        "patterns_evaluated_total": patterns_evaluated_total,
        "total_benchmark_time_sec": round(total_time, 4),
        "average_detection_latency_ms": round(avg_latency, 4),
        "maximum_detection_latency_ms": round(max_latency, 4),
    }


if __name__ == "__main__":
    results = run_behavior_performance_benchmark()
    print("AgentShield Phase 24 Performance Benchmark Results:")
    for k, v in results.items():
        print(f"  {k}: {v}")
