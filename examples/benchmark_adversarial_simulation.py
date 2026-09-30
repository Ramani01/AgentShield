"""
Phase 28 Safe Adversarial Simulation Synthetic Benchmark.
"""

import time
from agentshield import AgentShield
from agentshield.simulation import SimulationExecutor, ScenarioRegistry


def run_benchmark(iterations: int = 100):
    shield = AgentShield()
    executor = shield.simulation_executor
    registry = ScenarioRegistry(include_defaults=True)
    scenarios = registry.list_scenarios()

    total_scenarios = len(scenarios) * iterations
    start_time = time.perf_counter()
    latencies = []

    for _ in range(iterations):
        for s in scenarios:
            t0 = time.perf_counter()
            executor.execute_scenario(s.scenario_id, tenant_id="bench_t", agent_id="bench_a")
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000.0)

    total_time = time.perf_counter() - start_time
    avg_latency = sum(latencies) / len(latencies)
    max_latency = max(latencies)
    throughput = total_scenarios / total_time

    print(f"=== Phase 28 Safe Adversarial Simulation Benchmark ===")
    print(f"Iterations:                 {iterations}")
    print(f"Scenarios per Iteration:    {len(scenarios)}")
    print(f"Total Scenarios Evaluated:  {total_scenarios}")
    print(f"Total Time:                 {total_time:.4f} s")
    print(f"Average Latency per Scenario: {avg_latency:.4f} ms")
    print(f"Max Latency:                {max_latency:.4f} ms")
    print(f"Throughput:                 {throughput:.2f} scenarios/sec")


if __name__ == "__main__":
    run_benchmark(100)
