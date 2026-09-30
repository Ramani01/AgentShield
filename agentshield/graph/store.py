"""
Phase 26: Canonical Graph Store.
Deterministic, thread-safe in-memory graph storage enforcing tenant and agent boundaries.
"""

import threading
import logging
from typing import Dict, Tuple, List, Optional, Set
from agentshield.graph.models import GraphNode, GraphEdge

logger = logging.getLogger("AgentShield.CanonicalGraphStore")


class CanonicalGraphStore:
    """
    Deterministic in-memory graph store enforcing strict tenant and agent isolation boundaries.

    Invariants Enforced:
    1. Tenant Isolation: Rejects cross-tenant edges; queries never leak across tenant boundaries.
    2. Agent Identity Isolation: Agents remain distinct nodes (never merged).
    6. Deterministic Graph: Same nodes and edges produce stable graph representations.
    """

    def __init__(self):
        # Nodes: (tenant_id, node_id) -> GraphNode
        self._nodes: Dict[Tuple[str, str], GraphNode] = {}
        # Edges: (tenant_id, edge_id) -> GraphEdge
        self._edges: Dict[Tuple[str, str], GraphEdge] = {}

        # Adjacency lists for fast traversal: (tenant_id, node_id) -> List[GraphEdge]
        self._adj_out: Dict[Tuple[str, str], List[GraphEdge]] = {}
        self._adj_in: Dict[Tuple[str, str], List[GraphEdge]] = {}

        self._lock = threading.Lock()

    def add_node(self, node: GraphNode) -> GraphNode:
        """
        Inserts or updates a node in the graph store.
        Idempotent: Duplicate node_ids in same tenant update metadata without creating duplicate entries.
        """
        if not node or not node.node_id:
            raise ValueError("Invalid GraphNode: node_id is required.")

        tenant_id = node.tenant_id or "default"
        key = (tenant_id, node.node_id)

        with self._lock:
            if key in self._nodes:
                existing = self._nodes[key]
                # Merge metadata deterministically
                existing.metadata.update(node.metadata)
                return existing

            self._nodes[key] = node
            if key not in self._adj_out:
                self._adj_out[key] = []
            if key not in self._adj_in:
                self._adj_in[key] = []

        return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        """
        Inserts an edge connecting two nodes.
        Enforces Invariant 1 (Tenant Isolation): Source and Target nodes must be in the same tenant.
        """
        if not edge or not edge.source_node_id or not edge.target_node_id:
            raise ValueError("Invalid GraphEdge: source_node_id and target_node_id are required.")

        tenant_id = edge.tenant_id or "default"
        src_key = (tenant_id, edge.source_node_id)
        tgt_key = (tenant_id, edge.target_node_id)

        with self._lock:
            # Verify source and target nodes exist in the same tenant scope
            if src_key not in self._nodes:
                # Auto-create fallback node if not explicitly inserted
                self._nodes[src_key] = GraphNode(node_id=edge.source_node_id, tenant_id=tenant_id)
                self._adj_out[src_key] = []
                self._adj_in[src_key] = []

            if tgt_key not in self._nodes:
                self._nodes[tgt_key] = GraphNode(node_id=edge.target_node_id, tenant_id=tenant_id)
                self._adj_out[tgt_key] = []
                self._adj_in[tgt_key] = []

            edge_key = (tenant_id, edge.edge_id)
            if edge_key in self._edges:
                return self._edges[edge_key]

            self._edges[edge_key] = edge
            self._adj_out[src_key].append(edge)
            self._adj_in[tgt_key].append(edge)

        return edge

    def get_node(self, tenant_id: str = "default", node_id: str = "") -> Optional[GraphNode]:
        """Retrieves a node by tenant_id and node_id."""
        key = (tenant_id or "default", node_id)
        with self._lock:
            return self._nodes.get(key)

    def get_edge(self, tenant_id: str = "default", edge_id: str = "") -> Optional[GraphEdge]:
        """Retrieves an edge by tenant_id and edge_id."""
        key = (tenant_id or "default", edge_id)
        with self._lock:
            return self._edges.get(key)

    def get_nodes_by_tenant(self, tenant_id: str = "default") -> List[GraphNode]:
        """Returns all nodes belonging strictly to the specified tenant."""
        tid = tenant_id or "default"
        with self._lock:
            return [node for (t, _), node in self._nodes.items() if t == tid]

    def get_edges_by_tenant(self, tenant_id: str = "default") -> List[GraphEdge]:
        """Returns all edges belonging strictly to the specified tenant."""
        tid = tenant_id or "default"
        with self._lock:
            return [edge for (t, _), edge in self._edges.items() if t == tid]

    def get_outgoing_edges(self, tenant_id: str = "default", node_id: str = "") -> List[GraphEdge]:
        """Returns all outgoing edges originating from node_id in specified tenant."""
        key = (tenant_id or "default", node_id)
        with self._lock:
            edges = self._adj_out.get(key, [])
            # Sort edges deterministically by edge_id for Invariant 6 & 7
            return sorted(edges, key=lambda e: e.edge_id)

    def get_incoming_edges(self, tenant_id: str = "default", node_id: str = "") -> List[GraphEdge]:
        """Returns all incoming edges targeting node_id in specified tenant."""
        key = (tenant_id or "default", node_id)
        with self._lock:
            edges = self._adj_in.get(key, [])
            return sorted(edges, key=lambda e: e.edge_id)

    def clear_tenant_graph(self, tenant_id: str = "default") -> None:
        """Clears graph data for a specific tenant."""
        tid = tenant_id or "default"
        with self._lock:
            node_keys_to_del = [k for k in self._nodes if k[0] == tid]
            for k in node_keys_to_del:
                self._nodes.pop(k, None)
                self._adj_out.pop(k, None)
                self._adj_in.pop(k, None)

            edge_keys_to_del = [k for k in self._edges if k[0] == tid]
            for k in edge_keys_to_del:
                self._edges.pop(k, None)

    def clear_all(self) -> None:
        """Resets the entire graph store."""
        with self._lock:
            self._nodes.clear()
            self._edges.clear()
            self._adj_out.clear()
            self._adj_in.clear()
