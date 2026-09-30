"""
Unit and Integration Tests for Phase 26 Agent Security Graph & Attack-Path Tracking.
"""

import pytest
import time
from pathlib import Path

from agentshield import AgentShield
from agentshield.graph import (
    NodeType,
    RelationshipType,
    PathClassification,
    GraphNode,
    GraphEdge,
    SecurityPath,
    PathAssessment,
    CanonicalGraphStore,
    GraphEventAdapter,
    AttackPathAnalyzer,
    SecurityGraphEngine
)
from agentshield.provenance.logger import AuditLogger
from agentshield.behavior import BehaviorEventType, BehaviorAssessment
from agentshield.containment import IsolationLevel, ContainmentState


# =====================================================================
# 1. NODE & EDGE MODEL TESTS
# =====================================================================

def test_node_creation_and_hashing():
    n1 = GraphNode(node_id="agent:t1:a1", node_type=NodeType.AGENT, name="Agent-A1", tenant_id="t1")
    n2 = GraphNode(node_id="agent:t1:a1", node_type=NodeType.AGENT, name="Agent-A1", tenant_id="t1")

    assert n1.compute_node_hash() == n2.compute_node_hash()
    dict_repr = n1.to_dict()
    assert dict_repr["node_type"] == NodeType.AGENT
    assert "node_hash" in dict_repr


def test_edge_creation_and_hashing():
    e1 = GraphEdge(
        source_node_id="agent:t1:a1",
        target_node_id="tool:t1:python_exec",
        relationship_type=RelationshipType.INVOKES,
        tenant_id="t1"
    )
    dict_repr = e1.to_dict()
    assert dict_repr["relationship_type"] == RelationshipType.INVOKES
    assert "edge_hash" in dict_repr


# =====================================================================
# 2. GRAPH STORE & ISOLATION TESTS
# =====================================================================

def test_graph_store_insertion_and_lookup():
    store = CanonicalGraphStore()
    n = GraphNode(node_id="agent:t1:a1", node_type=NodeType.AGENT, tenant_id="t1")
    store.add_node(n)

    retrieved = store.get_node("t1", "agent:t1:a1")
    assert retrieved is not None
    assert retrieved.node_id == "agent:t1:a1"


def test_tenant_isolation_nodes_and_queries():
    store = CanonicalGraphStore()
    store.add_node(GraphNode(node_id="agent:t1:a1", tenant_id="t1"))
    store.add_node(GraphNode(node_id="agent:t2:a1", tenant_id="t2"))

    t1_nodes = store.get_nodes_by_tenant("t1")
    t2_nodes = store.get_nodes_by_tenant("t2")

    assert len(t1_nodes) == 1
    assert t1_nodes[0].node_id == "agent:t1:a1"
    assert len(t2_nodes) == 1
    assert t2_nodes[0].node_id == "agent:t2:a1"


def test_agent_identity_isolation():
    store = CanonicalGraphStore()
    n1 = GraphNode(node_id="agent:t1:a1", node_type=NodeType.AGENT, tenant_id="t1")
    n2 = GraphNode(node_id="agent:t1:a2", node_type=NodeType.AGENT, tenant_id="t1")
    tool = GraphNode(node_id="tool:t1:shared_tool", node_type=NodeType.TOOL, tenant_id="t1")

    store.add_node(n1)
    store.add_node(n2)
    store.add_node(tool)

    store.add_edge(GraphEdge(source_node_id=n1.node_id, target_node_id=tool.node_id, relationship_type=RelationshipType.INVOKES, tenant_id="t1"))
    store.add_edge(GraphEdge(source_node_id=n2.node_id, target_node_id=tool.node_id, relationship_type=RelationshipType.INVOKES, tenant_id="t1"))

    # Verify both agent nodes remain distinct despite sharing a tool node
    assert store.get_node("t1", "agent:t1:a1") != store.get_node("t1", "agent:t1:a2")
    assert len(store.get_nodes_by_tenant("t1")) == 3


# =====================================================================
# 3. PATH TRAVERSAL & ANALYSIS TESTS
# =====================================================================

def test_simple_path_traversal():
    store = CanonicalGraphStore()
    analyzer = AttackPathAnalyzer(store=store)

    n_agent = GraphNode(node_id="agent:t1:a1", node_type=NodeType.AGENT, tenant_id="t1")
    n_tool = GraphNode(node_id="tool:t1:db_query", node_type=NodeType.TOOL, tenant_id="t1")
    n_res = GraphNode(node_id="resource:t1:sql_db", node_type=NodeType.RESOURCE, tenant_id="t1")

    store.add_node(n_agent)
    store.add_node(n_tool)
    store.add_node(n_res)

    store.add_edge(GraphEdge(source_node_id=n_agent.node_id, target_node_id=n_tool.node_id, relationship_type=RelationshipType.INVOKES, tenant_id="t1"))
    store.add_edge(GraphEdge(source_node_id=n_tool.node_id, target_node_id=n_res.node_id, relationship_type=RelationshipType.ACCESSES, tenant_id="t1"))

    paths = analyzer.find_paths("t1", n_agent.node_id, n_res.node_id)
    assert len(paths) == 1
    assert paths[0].length == 2
    assert paths[0].nodes[0].node_id == n_agent.node_id
    assert paths[0].nodes[2].node_id == n_res.node_id


def test_cycle_protection():
    store = CanonicalGraphStore()
    analyzer = AttackPathAnalyzer(store=store)

    # Cyclic graph: Agent -> Tool -> Agent
    n_agent = GraphNode(node_id="agent:t1:a1", node_type=NodeType.AGENT, tenant_id="t1")
    n_tool = GraphNode(node_id="tool:t1:looper", node_type=NodeType.TOOL, tenant_id="t1")

    store.add_node(n_agent)
    store.add_node(n_tool)

    store.add_edge(GraphEdge(source_node_id=n_agent.node_id, target_node_id=n_tool.node_id, relationship_type=RelationshipType.INVOKES, tenant_id="t1"))
    store.add_edge(GraphEdge(source_node_id=n_tool.node_id, target_node_id=n_agent.node_id, relationship_type=RelationshipType.PRODUCES, tenant_id="t1"))

    # Traversal should execute safely without infinite loop
    paths = analyzer.find_paths("t1", n_agent.node_id, max_depth=5)
    assert len(paths) >= 1
    # Check that visited nodes are not endlessly duplicated in cycle
    for p in paths:
        assert p.length <= 5


def test_cross_tenant_path_isolation():
    store = CanonicalGraphStore()
    analyzer = AttackPathAnalyzer(store=store)

    store.add_node(GraphNode(node_id="agent:t1:a1", tenant_id="t1"))
    store.add_node(GraphNode(node_id="resource:t2:secret_doc", tenant_id="t2"))

    # Querying tenant t1 for paths to resource in tenant t2
    paths = analyzer.find_paths("t1", "agent:t1:a1", "resource:t2:secret_doc")
    assert len(paths) == 0


# =====================================================================
# 4. SECURITY INVARIANT & INTEGRATION TESTS
# =====================================================================

def test_invariant_10_neutral_path_classification():
    store = CanonicalGraphStore()
    analyzer = AttackPathAnalyzer(store=store)

    n_agent = GraphNode(node_id="agent:t1:a1", node_type=NodeType.AGENT, tenant_id="t1")
    n_comm = GraphNode(node_id="endpoint:t1:api.ext", node_type=NodeType.COMMUNICATION_TARGET, tenant_id="t1")

    store.add_node(n_agent)
    store.add_node(n_comm)
    store.add_edge(GraphEdge(source_node_id=n_agent.node_id, target_node_id=n_comm.node_id, relationship_type=RelationshipType.COMMUNICATES_WITH, tenant_id="t1"))

    paths = analyzer.find_paths("t1", n_agent.node_id, n_comm.node_id)
    assert len(paths) == 1
    # Classification must be neutral (OBSERVED or SUSPICIOUS)
    assert paths[0].classification in (PathClassification.OBSERVED, PathClassification.SUSPICIOUS)


def test_security_graph_engine_ingest_and_assess():
    engine = SecurityGraphEngine()

    tenant_id = "t1"
    agent_id = "a1"

    engine.ingest_capability_grant(tenant_id, agent_id, "data:read")
    engine.ingest_tool_invocation(tenant_id, agent_id, "file_reader", resource="secret.pdf")
    engine.ingest_communication_event(tenant_id, agent_id, "https://exfil.external.com")
    engine.ingest_behavior_pattern_trigger(tenant_id, agent_id, "BEHAVIOR-001", "Sensitive Data Escalation")
    engine.ingest_containment_record(tenant_id, agent_id, ContainmentState.CONTAINED, IsolationLevel.FULL)

    assessment = engine.find_agent_attack_paths(tenant_id, agent_id)
    assert len(assessment.paths) >= 1
    assert "SIGNAL_COMMUNICATION_AFTER_DATA_ACCESS" in assessment.signals or "SIGNAL_BEHAVIORAL_PATTERN_TRIGGERED" in assessment.signals
    assert assessment.risk_level in ("HIGH", "CRITICAL")


def test_audit_logger_integration(tmp_path):
    log_file = tmp_path / "graph_audit.jsonl"
    logger = AuditLogger(log_file_path=str(log_file))
    engine = SecurityGraphEngine(audit_logger=logger)

    engine.ingest_tool_invocation("t1", "a1", "exec_tool", "data.json")
    assessment = engine.find_agent_attack_paths("t1", "a1")

    integrity = logger.verify_log_integrity()
    assert integrity["valid"] is True


def test_agentshield_facade_graph_integration():
    shield = AgentShield()
    assert hasattr(shield, "graph_engine")
    assert isinstance(shield.graph_engine, SecurityGraphEngine)

    shield.graph_engine.ingest_tool_invocation("facade_t", "facade_a", "search_tool")
    q = shield.graph_engine.query_graph("facade_t")
    assert q["node_count"] >= 2
    assert q["edge_count"] >= 1
