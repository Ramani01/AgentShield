"""
Synthetic Demonstration of AgentShield Phase 26 Agent Security Graph.
"""

from agentshield import AgentShield
from agentshield.containment import IsolationLevel, ContainmentState


def run_security_graph_demo():
    print("=== AgentShield Phase 26 Security Graph Demo ===")
    shield = AgentShield()

    tenant_id = "finance_tenant"
    agent_id = "analyst_bot"

    print("\n1. Ingesting Multi-Step Operations into Security Graph...")
    shield.graph_engine.ingest_capability_grant(tenant_id, agent_id, "finance:read")
    shield.graph_engine.ingest_tool_invocation(tenant_id, agent_id, "file_fetcher", resource="q3_earnings_draft.pdf")
    shield.graph_engine.ingest_behavior_event(tenant_id, agent_id, "READ_MEMORY", resource="vault_key_store")
    shield.graph_engine.ingest_communication_event(tenant_id, agent_id, "https://analytics.partner-org.com")
    shield.graph_engine.ingest_behavior_pattern_trigger(tenant_id, agent_id, "BEHAVIOR-001", "Sensitive Data Escalation")
    shield.graph_engine.ingest_containment_record(tenant_id, agent_id, ContainmentState.CONTAINED, IsolationLevel.FULL)

    print("\n2. Querying Graph Metadata...")
    graph_data = shield.graph_engine.query_graph(tenant_id)
    print(f"   Nodes in Graph: {graph_data['node_count']}")
    print(f"   Edges in Graph: {graph_data['edge_count']}")

    print("\n3. Discovering Agent Security Paths & Risk Signals...")
    assessment = shield.graph_engine.find_agent_attack_paths(tenant_id, agent_id, max_depth=5)
    print(f"   Security Paths Found: {len(assessment.paths)}")
    print(f"   Assessed Risk Level:  {assessment.risk_level}")
    print(f"   Detected Signals:     {assessment.signals}")

    print("\n4. Inspected Sample Security Path:")
    if assessment.paths:
        sample_path = assessment.paths[0]
        print(f"   Path Length:         {sample_path.length}")
        print(f"   Classification:      {sample_path.classification}")
        print(f"   Node Sequence:       {' -> '.join([n.name for n in sample_path.nodes])}")

    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    run_security_graph_demo()
