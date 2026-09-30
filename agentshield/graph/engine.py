"""
Phase 26: Security Graph Engine.
Main facade orchestrator for Agent Security Graph & Attack-Path Tracking.
"""

import logging
from typing import Optional, Dict, Any, List
from agentshield.graph.models import GraphNode, GraphEdge, SecurityPath, PathAssessment
from agentshield.graph.store import CanonicalGraphStore
from agentshield.graph.builder import GraphEventAdapter
from agentshield.graph.analyzer import AttackPathAnalyzer

logger = logging.getLogger("AgentShield.SecurityGraphEngine")


class SecurityGraphEngine:
    """
    Main Phase 26 Security Graph Engine.

    Security Invariants Enforced:
    1. Tenant Isolation: Graph queries/paths never expose cross-tenant data.
    2. Agent Identity Isolation: Shared tools/resources do not merge agent identities.
    3. No Authorization Elevation: Graph relationships cannot grant capabilities.
    4. No Policy Override: Graph analysis cannot override capability, communication, egress, or containment policies.
    5. Provenance Preservation: Edges retain source controls and evidence.
    6. Deterministic Graph: Identical events produce identical graph structures.
    7. Deterministic Path Search: Identical graph + query produces identical paths.
    8. Bounded Traversal: Traversal depth is strictly capped (max_depth).
    9. Cycle Safety: Cycles do not cause infinite loops during path search.
    10. No Unsupported Attribution: Uses neutral classifications (OBSERVED, SUSPICIOUS).
    11. No Cross-Agent Collapse: Different agents remain distinct graph nodes.
    12. Previous Controls Authoritative: Controls 01-13 & Phases 21-25 remain authoritative.
    """

    def __init__(
        self,
        store: Optional[CanonicalGraphStore] = None,
        audit_logger: Optional[Any] = None
    ):
        self.store = store or CanonicalGraphStore()
        self.adapter = GraphEventAdapter(store=self.store)
        self.analyzer = AttackPathAnalyzer(store=self.store)
        self.audit_logger = audit_logger

    def ingest_capability_grant(self, tenant_id: str, agent_id: str, capability: str):
        """Ingests a capability grant into the security graph."""
        return self.adapter.ingest_capability_grant(tenant_id, agent_id, capability)

    def ingest_tool_invocation(self, tenant_id: str, agent_id: str, tool_name: str, resource: Optional[str] = None):
        """Ingests a tool invocation and resource access into the security graph."""
        return self.adapter.ingest_tool_invocation(tenant_id, agent_id, tool_name, resource)

    def ingest_communication_event(self, tenant_id: str, agent_id: str, target_endpoint: str):
        """Ingests an external communication event into the security graph."""
        return self.adapter.ingest_communication_event(tenant_id, agent_id, target_endpoint)

    def ingest_behavior_event(self, tenant_id: str, agent_id: str, event_type: str, resource: Optional[str] = None):
        """Ingests a behavioral event into the security graph."""
        return self.adapter.ingest_behavior_event(tenant_id, agent_id, event_type, resource)

    def ingest_behavior_pattern_trigger(self, tenant_id: str, agent_id: str, pattern_id: str, pattern_name: str):
        """Ingests a Phase 24 behavioral pattern trigger into the security graph."""
        return self.adapter.ingest_behavior_pattern_trigger(tenant_id, agent_id, pattern_id, pattern_name)

    def ingest_containment_record(self, tenant_id: str, agent_id: str, containment_state: str, isolation_level: str):
        """Ingests a Phase 25 containment record into the security graph."""
        return self.adapter.ingest_containment_record(tenant_id, agent_id, containment_state, isolation_level)

    def find_agent_attack_paths(
        self, tenant_id: str = "default", agent_id: str = "", max_depth: int = 5
    ) -> PathAssessment:
        """
        Searches graph for security relationship paths originating from agent_id.
        Returns PathAssessment.
        """
        assessment = self.analyzer.assess_agent_paths(tenant_id=tenant_id, agent_id=agent_id, max_depth=max_depth)

        if self.audit_logger and assessment.paths:
            try:
                self.audit_logger.log_event(
                    "SECURITY_GRAPH_PATH_DISCOVERED",
                    {
                        "tenant_id": tenant_id,
                        "agent_id": agent_id,
                        "paths_count": len(assessment.paths),
                        "risk_level": assessment.risk_level,
                        "signals": assessment.signals
                    },
                    tenant_id=tenant_id
                )
            except Exception as e:
                logger.warning(f"Audit logger error in SecurityGraphEngine: {e}")

        return assessment

    def query_graph(self, tenant_id: str = "default", node_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Queries the stored graph strictly within tenant_id boundary.
        """
        nodes = self.store.get_nodes_by_tenant(tenant_id)
        if node_type:
            nodes = [n for n in nodes if n.node_type == node_type]
        edges = self.store.get_edges_by_tenant(tenant_id)

        return {
            "tenant_id": tenant_id,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": [n.to_dict() for n in nodes],
            "edges": [e.to_dict() for e in edges]
        }
