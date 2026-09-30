"""
Phase 26: Attack-Path Analyzer.
Traverses security graphs, discovers relationship paths, and evaluates risk signals safely.
"""

from typing import List, Dict, Any, Optional, Set
from agentshield.graph.models import (
    GraphNode,
    GraphEdge,
    NodeType,
    RelationshipType,
    PathClassification,
    SecurityPath,
    PathAssessment
)
from agentshield.graph.store import CanonicalGraphStore


class AttackPathAnalyzer:
    """
    Analyzes security graphs to discover relationship paths and evaluate risk signals.

    Invariants Enforced:
    1. Tenant Isolation: Traversal queries operate strictly within tenant_id scope.
    5. Provenance Preservation: Retains originating evidence and edge metadata.
    7. Deterministic Path Search: Same graph + query produces identical ordered paths.
    8. Bounded Traversal: Traversal depth is bounded by max_depth.
    9. Cycle Safety: Tracks visited nodes on path stack to prevent infinite loops.
    10. No Unsupported Attribution: Uses neutral classifications (OBSERVED, SUSPICIOUS).
    """

    def __init__(self, store: CanonicalGraphStore):
        self.store = store

    def find_paths(
        self,
        tenant_id: str = "default",
        source_node_id: str = "",
        target_node_id: Optional[str] = None,
        max_depth: int = 5
    ) -> List[SecurityPath]:
        """
        Discovers all paths from source_node_id up to max_depth within tenant_id.
        Cycle-safe and deterministic.
        """
        tid = tenant_id or "default"
        src_node = self.store.get_node(tid, source_node_id)
        if not src_node:
            return []

        max_d = max(1, min(max_depth, 10))  # Enforce bounded depth (Invariant 8)

        discovered_paths: List[SecurityPath] = []

        # DFS with explicit stack: (current_node_id, path_nodes, path_edges, visited_set)
        stack: List[Tuple[str, List[GraphNode], List[GraphEdge], Set[str]]] = [
            (src_node.node_id, [src_node], [], {src_node.node_id})
        ]

        while stack:
            curr_id, path_nodes, path_edges, visited = stack.pop()

            if len(path_edges) > 0 and (target_node_id is None or curr_id == target_node_id):
                sec_path = SecurityPath(
                    tenant_id=tid,
                    source_node_id=source_node_id,
                    target_node_id=curr_id,
                    nodes=list(path_nodes),
                    edges=list(path_edges),
                    length=len(path_edges),
                    classification=PathClassification.OBSERVED,
                    evidence={
                        "node_ids": [n.node_id for n in path_nodes],
                        "edge_ids": [e.edge_id for e in path_edges],
                        "relationship_chain": [e.relationship_type for e in path_edges]
                    }
                )
                discovered_paths.append(sec_path)
                if target_node_id and curr_id == target_node_id:
                    continue

            if len(path_edges) >= max_d:
                continue

            outgoing = self.store.get_outgoing_edges(tid, curr_id)
            for edge in reversed(outgoing):  # Stack pops in order
                next_id = edge.target_node_id
                # Cycle Safety (Invariant 9): Skip if already in current path stack
                if next_id in visited:
                    continue

                next_node = self.store.get_node(tid, next_id)
                if next_node:
                    new_nodes = path_nodes + [next_node]
                    new_edges = path_edges + [edge]
                    new_visited = visited | {next_id}
                    stack.append((next_id, new_nodes, new_edges, new_visited))

        # Deterministic Path Search (Invariant 7): Sort paths deterministically
        discovered_paths.sort(key=lambda p: (p.length, [n.node_id for n in p.nodes]))
        return discovered_paths

    def find_agent_paths(
        self, tenant_id: str = "default", agent_id: str = "", max_depth: int = 5
    ) -> List[SecurityPath]:
        """Discovers all paths originating from the specified agent."""
        agent_node_id = f"agent:{tenant_id}:{agent_id}"
        return self.find_paths(tenant_id=tenant_id, source_node_id=agent_node_id, max_depth=max_depth)

    def assess_agent_paths(
        self, tenant_id: str = "default", agent_id: str = "", max_depth: int = 5
    ) -> PathAssessment:
        """
        Evaluates graph paths originating from an agent and outputs a PathAssessment with risk signals.
        """
        paths = self.find_agent_paths(tenant_id=tenant_id, agent_id=agent_id, max_depth=max_depth)
        signals: List[str] = []
        risk_level = "LOW"

        has_data_read = False
        has_ext_comm = False
        has_pattern = False
        has_containment = False

        for path in paths:
            rel_chain = [e.relationship_type for e in path.edges]
            node_types = [n.node_type for n in path.nodes]

            if NodeType.RESOURCE in node_types or RelationshipType.READS in rel_chain:
                has_data_read = True

            if NodeType.COMMUNICATION_TARGET in node_types or RelationshipType.COMMUNICATES_WITH in rel_chain:
                has_ext_comm = True

            if NodeType.BEHAVIOR_PATTERN in node_types or RelationshipType.TRIGGERS in rel_chain:
                has_pattern = True
                path.classification = PathClassification.SUSPICIOUS

            if NodeType.CONTAINMENT_STATE in node_types or RelationshipType.CONTAINED_BY in rel_chain:
                has_containment = True

        if has_data_read and has_ext_comm:
            signals.append("SIGNAL_COMMUNICATION_AFTER_DATA_ACCESS")
            risk_level = "HIGH"

        if has_pattern:
            signals.append("SIGNAL_BEHAVIORAL_PATTERN_TRIGGERED")
            risk_level = "HIGH"

        if has_containment:
            signals.append("SIGNAL_AGENT_CONTAINMENT_ACTIVE")

        if has_pattern and has_ext_comm and has_data_read:
            risk_level = "CRITICAL"

        evidence = {
            "agent_id": agent_id,
            "paths_evaluated": len(paths),
            "containment_active": has_containment,
            "behavior_pattern_detected": has_pattern
        }

        return PathAssessment(
            tenant_id=tenant_id,
            paths=paths,
            signals=signals,
            risk_level=risk_level,
            evidence=evidence
        )
