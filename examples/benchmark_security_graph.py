"""
Performance Benchmark Script for Phase 26 Security Graph & Path Tracking.
"""

import time
from typing import Dict, Any
from agentshield.graph import SecurityGraphEngine


def run_graph_performance_benchmark(
    num_tenants: int = 5,
    agents_per_tenant: int = 10,
    hops_per_agent: int = 4
) -> Dict[str, Any]:
    engine = SecurityGraphEngine()

    total_agents = num_tenants * agents_per_tenant
    insertion_latencies = []

    # 1. Benchmark Graph Insertion Latency
    start_ingest = time.perf_counter()

    for t_idx in range(num_tenants):
        tenant_id = f"bench_tenant_{t_idx}"
        for a_idx in range(agents_per_tenant):
            agent_id = f"agent_{a_idx}"
            t0 = time.perf_counter()
            engine.ingest_capability_grant(tenant_id, agent_id, f"cap_{a_idx}")
            engine.ingest_tool_invocation(tenant_id, agent_id, f"tool_{a_idx}", resource=f"res_{a_idx}.doc")
            engine.ingest_communication_event(tenant_id, agent_id, f"https://endpoint_{a_idx}.com")
            engine.ingest_behavior_pattern_trigger(tenant_id, agent_id, f"PAT-{a_idx}", f"Pattern-{a_idx}")
            t1 = time.perf_counter()
            insertion_latencies.append((t1 - t0) * 1000.0)

    total_nodes = sum(engine.query_graph(f"bench_tenant_{t}")["node_count"] for t in range(num_tenants))
    total_edges = sum(engine.query_graph(f"bench_tenant_{t}")["edge_count"] for t in range(num_tenants))

    # 2. Benchmark Path Search Latency
    path_latencies = []
    paths_searched_count = 0

    max_traversal_depth = hops_per_agent

    start_search = time.perf_counter()

    for t_idx in range(num_tenants):
        tenant_id = f"bench_tenant_{t_idx}"
        for a_idx in range(agents_per_tenant):
            agent_id = f"agent_{a_idx}"
            t0 = time.perf_counter()
            assessment = engine.find_agent_attack_paths(tenant_id, agent_id, max_depth=max_traversal_depth)
            t1 = time.perf_counter()
            path_latencies.append((t1 - t0) * 1000.0)
            paths_searched_count += len(assessment.paths)

    avg_insert_lat = sum(insertion_latencies) / len(insertion_latencies) if insertion_latencies else 0.0
    avg_path_lat = sum(path_latencies) / len(path_latencies) if path_latencies else 0.0
    max_path_lat = max(path_latencies) if path_latencies else 0.0

    return {
        "number_of_tenants": num_tenants,
        "number_of_agents": total_agents,
        "number_of_graph_nodes": total_nodes,
        "number_of_graph_edges": total_edges,
        "number_of_paths_searched": paths_searched_count,
        "maximum_traversal_depth": max_traversal_depth,
        "average_graph_insertion_latency_ms": round(avg_insert_lat, 4),
        "average_path_search_latency_ms": round(avg_path_lat, 4),
        "maximum_path_search_latency_ms": round(max_path_lat, 4),
    }


if __name__ == "__main__":
    results = run_graph_performance_benchmark()
    print("AgentShield Phase 26 Performance Benchmark Results:")
    for k, v in results.items():
        print(f"  {k}: {v}")
