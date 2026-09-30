"""
Phase 26: Graph Event Adapter and Builder.
Converts security-relevant events into graph nodes and edges across Phases 1-25.
"""

from typing import Tuple, Optional, Dict, Any, List
from agentshield.graph.models import GraphNode, GraphEdge, NodeType, RelationshipType
from agentshield.graph.store import CanonicalGraphStore


class GraphEventAdapter:
    """
    Adapter converting AgentShield security events into graph entities.

    Invariants Enforced:
    1. Tenant Isolation: All created nodes/edges are explicitly scoped to tenant_id.
    2. Agent Identity Isolation: Preserves unique agent node_id (no identity collapse).
    5. Provenance Preservation: Edges retain source_control and metadata references.
    """

    def __init__(self, store: CanonicalGraphStore):
        self.store = store

    def get_or_create_agent_node(self, tenant_id: str, agent_id: str) -> GraphNode:
        """Retrieves or creates a unique AGENT node."""
        node_id = f"agent:{tenant_id}:{agent_id}"
        node = GraphNode(
            node_id=node_id,
            node_type=NodeType.AGENT,
            name=f"Agent-{agent_id}",
            tenant_id=tenant_id
        )
        return self.store.add_node(node)

    def ingest_capability_grant(
        self, tenant_id: str, agent_id: str, capability: str
    ) -> Tuple[GraphNode, GraphNode, GraphEdge]:
        """Creates AGENT -> AUTHORIZED_FOR -> CAPABILITY edge."""
        agent_node = self.get_or_create_agent_node(tenant_id, agent_id)
        cap_node_id = f"capability:{tenant_id}:{capability}"
        cap_node = self.store.add_node(GraphNode(
            node_id=cap_node_id,
            node_type=NodeType.CAPABILITY,
            name=capability,
            tenant_id=tenant_id
        ))

        edge = GraphEdge(
            source_node_id=agent_node.node_id,
            target_node_id=cap_node.node_id,
            relationship_type=RelationshipType.AUTHORIZED_FOR,
            tenant_id=tenant_id,
            source_control="PHASE_21_CAPABILITY_ENGINE"
        )
        self.store.add_edge(edge)
        return agent_node, cap_node, edge

    def ingest_tool_invocation(
        self, tenant_id: str, agent_id: str, tool_name: str, resource: Optional[str] = None
    ) -> List[GraphEdge]:
        """Creates AGENT -> INVOKES -> TOOL edge and optional TOOL -> ACCESSES -> RESOURCE edge."""
        agent_node = self.get_or_create_agent_node(tenant_id, agent_id)
        tool_node_id = f"tool:{tenant_id}:{tool_name}"
        tool_node = self.store.add_node(GraphNode(
            node_id=tool_node_id,
            node_type=NodeType.TOOL,
            name=tool_name,
            tenant_id=tenant_id
        ))

        edges = []
        e1 = GraphEdge(
            source_node_id=agent_node.node_id,
            target_node_id=tool_node.node_id,
            relationship_type=RelationshipType.INVOKES,
            tenant_id=tenant_id,
            source_control="PHASE_12_TOOL_GOVERNANCE"
        )
        edges.append(self.store.add_edge(e1))

        if resource:
            res_node_id = f"resource:{tenant_id}:{resource}"
            res_node = self.store.add_node(GraphNode(
                node_id=res_node_id,
                node_type=NodeType.RESOURCE,
                name=resource,
                tenant_id=tenant_id
            ))
            e2 = GraphEdge(
                source_node_id=tool_node.node_id,
                target_node_id=res_node.node_id,
                relationship_type=RelationshipType.ACCESSES,
                tenant_id=tenant_id,
                source_control="PHASE_12_TOOL_GOVERNANCE"
            )
            edges.append(self.store.add_edge(e2))

        return edges

    def ingest_communication_event(
        self, tenant_id: str, agent_id: str, target_endpoint: str
    ) -> Tuple[GraphNode, GraphNode, GraphEdge]:
        """Creates AGENT -> COMMUNICATES_WITH -> COMMUNICATION_TARGET edge."""
        agent_node = self.get_or_create_agent_node(tenant_id, agent_id)
        comm_node_id = f"endpoint:{tenant_id}:{target_endpoint}"
        comm_node = self.store.add_node(GraphNode(
            node_id=comm_node_id,
            node_type=NodeType.COMMUNICATION_TARGET,
            name=target_endpoint,
            tenant_id=tenant_id
        ))

        edge = GraphEdge(
            source_node_id=agent_node.node_id,
            target_node_id=comm_node.node_id,
            relationship_type=RelationshipType.COMMUNICATES_WITH,
            tenant_id=tenant_id,
            source_control="PHASE_22_COMMUNICATION_POLICY"
        )
        self.store.add_edge(edge)
        return agent_node, comm_node, edge

    def ingest_behavior_event(
        self, tenant_id: str, agent_id: str, event_type: str, resource: Optional[str] = None
    ) -> Tuple[GraphNode, GraphNode, GraphEdge]:
        """Creates AGENT -> PRODUCES -> BEHAVIOR_EVENT edge."""
        agent_node = self.get_or_create_agent_node(tenant_id, agent_id)
        evt_node_id = f"evt:{tenant_id}:{event_type}:{agent_node.node_id}"
        evt_node = self.store.add_node(GraphNode(
            node_id=evt_node_id,
            node_type=NodeType.BEHAVIOR_EVENT,
            name=event_type,
            tenant_id=tenant_id,
            metadata={"resource": resource}
        ))

        edge = GraphEdge(
            source_node_id=agent_node.node_id,
            target_node_id=evt_node.node_id,
            relationship_type=RelationshipType.PRODUCES,
            tenant_id=tenant_id,
            source_control="PHASE_24_BEHAVIORAL_DETECTOR"
        )
        self.store.add_edge(edge)

        # Connect event to resource if specified
        if resource:
            res_node_id = f"resource:{tenant_id}:{resource}"
            res_node = self.store.add_node(GraphNode(
                node_id=res_node_id,
                node_type=NodeType.RESOURCE,
                name=resource,
                tenant_id=tenant_id
            ))
            res_edge = GraphEdge(
                source_node_id=evt_node.node_id,
                target_node_id=res_node.node_id,
                relationship_type=RelationshipType.ACCESSES,
                tenant_id=tenant_id,
                source_control="PHASE_24_BEHAVIORAL_DETECTOR"
            )
            self.store.add_edge(res_edge)

        return agent_node, evt_node, edge

    def ingest_behavior_pattern_trigger(
        self, tenant_id: str, agent_id: str, pattern_id: str, pattern_name: str
    ) -> Tuple[GraphNode, GraphNode, GraphEdge]:
        """Creates AGENT -> TRIGGERS -> BEHAVIOR_PATTERN edge."""
        agent_node = self.get_or_create_agent_node(tenant_id, agent_id)
        pat_node_id = f"pattern:{tenant_id}:{pattern_id}"
        pat_node = self.store.add_node(GraphNode(
            node_id=pat_node_id,
            node_type=NodeType.BEHAVIOR_PATTERN,
            name=pattern_name,
            tenant_id=tenant_id,
            metadata={"pattern_id": pattern_id}
        ))

        edge = GraphEdge(
            source_node_id=agent_node.node_id,
            target_node_id=pat_node.node_id,
            relationship_type=RelationshipType.TRIGGERS,
            tenant_id=tenant_id,
            source_control="PHASE_24_BEHAVIORAL_DETECTOR"
        )
        self.store.add_edge(edge)
        return agent_node, pat_node, edge

    def ingest_containment_record(
        self, tenant_id: str, agent_id: str, containment_state: str, isolation_level: str
    ) -> Tuple[GraphNode, GraphNode, GraphEdge]:
        """Creates AGENT -> CONTAINED_BY -> CONTAINMENT_STATE edge."""
        agent_node = self.get_or_create_agent_node(tenant_id, agent_id)
        state_node_id = f"containment:{tenant_id}:{containment_state}"
        state_node = self.store.add_node(GraphNode(
            node_id=state_node_id,
            node_type=NodeType.CONTAINMENT_STATE,
            name=containment_state,
            tenant_id=tenant_id,
            metadata={"isolation_level": isolation_level}
        ))

        edge = GraphEdge(
            source_node_id=agent_node.node_id,
            target_node_id=state_node.node_id,
            relationship_type=RelationshipType.CONTAINED_BY,
            tenant_id=tenant_id,
            source_control="PHASE_25_CONTAINMENT_ENGINE"
        )
        self.store.add_edge(edge)
        return agent_node, state_node, edge
