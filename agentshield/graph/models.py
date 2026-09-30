"""
Phase 26: Agent Security Graph & Attack-Path Tracking Models.
"""

import time
import uuid
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional


class NodeType:
    """Strongly typed graph node classifications."""
    AGENT = "AGENT"
    PRINCIPAL = "PRINCIPAL"
    TENANT = "TENANT"
    CAPABILITY = "CAPABILITY"
    TOOL = "TOOL"
    RESOURCE = "RESOURCE"
    MEMORY = "MEMORY"
    COMMUNICATION_TARGET = "COMMUNICATION_TARGET"
    BEHAVIOR_EVENT = "BEHAVIOR_EVENT"
    BEHAVIOR_PATTERN = "BEHAVIOR_PATTERN"
    CONTAINMENT_STATE = "CONTAINMENT_STATE"
    CHECKPOINT = "CHECKPOINT"
    RUNTIME_STATE = "RUNTIME_STATE"

    @classmethod
    def all_types(cls) -> List[str]:
        return [
            cls.AGENT, cls.PRINCIPAL, cls.TENANT, cls.CAPABILITY, cls.TOOL,
            cls.RESOURCE, cls.MEMORY, cls.COMMUNICATION_TARGET, cls.BEHAVIOR_EVENT,
            cls.BEHAVIOR_PATTERN, cls.CONTAINMENT_STATE, cls.CHECKPOINT, cls.RUNTIME_STATE
        ]


class RelationshipType:
    """Strongly typed graph edge relationship types."""
    OWNS = "OWNS"
    AUTHORIZED_FOR = "AUTHORIZED_FOR"
    USES = "USES"
    ACCESSES = "ACCESSES"
    READS = "READS"
    WRITES = "WRITES"
    INVOKES = "INVOKES"
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    PRODUCES = "PRODUCES"
    TRIGGERS = "TRIGGERS"
    OBSERVED_DURING = "OBSERVED_DURING"
    CONTAINED_BY = "CONTAINED_BY"
    RESTORED_FROM = "RESTORED_FROM"
    DERIVED_FROM = "DERIVED_FROM"
    CONNECTED_TO = "CONNECTED_TO"

    @classmethod
    def all_types(cls) -> List[str]:
        return [
            cls.OWNS, cls.AUTHORIZED_FOR, cls.USES, cls.ACCESSES, cls.READS, cls.WRITES,
            cls.INVOKES, cls.COMMUNICATES_WITH, cls.PRODUCES, cls.TRIGGERS,
            cls.OBSERVED_DURING, cls.CONTAINED_BY, cls.RESTORED_FROM, cls.DERIVED_FROM, cls.CONNECTED_TO
        ]


class PathClassification:
    """Neutral, non-attribution path security classifications."""
    OBSERVED = "OBSERVED"
    SUSPICIOUS = "SUSPICIOUS"
    UNKNOWN = "UNKNOWN"


@dataclass
class GraphNode:
    """Strongly typed graph node representing a security-relevant entity."""
    node_id: str
    node_type: str = NodeType.AGENT
    name: str = ""
    tenant_id: str = "default"
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def __post_init__(self):
        if not self.name:
            self.name = self.node_id
        if not self.tenant_id:
            self.tenant_id = "default"
        if not self.created_at:
            self.created_at = time.time()

    def compute_node_hash(self) -> str:
        """Computes a deterministic SHA-256 fingerprint for the node."""
        payload = {
            "tenant_id": self.tenant_id,
            "node_type": self.node_type,
            "node_id": self.node_id,
            "metadata": self.metadata
        }
        raw = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["node_hash"] = self.compute_node_hash()
        return res


@dataclass
class GraphEdge:
    """Strongly typed graph edge representing a security-relevant relationship."""
    edge_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_node_id: str = ""
    target_node_id: str = ""
    relationship_type: str = RelationshipType.CONNECTED_TO
    tenant_id: str = "default"
    timestamp: float = field(default_factory=time.time)
    source_control: Optional[str] = None
    confidence: float = 1.0
    provenance_ref: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.edge_id:
            payload = f"{self.tenant_id}:{self.source_node_id}:{self.relationship_type}:{self.target_node_id}"
            self.edge_id = f"edge_{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:12]}"
        if not self.timestamp:
            self.timestamp = time.time()

    def compute_edge_hash(self) -> str:
        """Computes a deterministic SHA-256 fingerprint for the edge."""
        payload = {
            "tenant_id": self.tenant_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "relationship_type": self.relationship_type,
            "source_control": self.source_control,
            "provenance_ref": self.provenance_ref,
            "metadata": self.metadata
        }
        raw = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["edge_hash"] = self.compute_edge_hash()
        return res


@dataclass
class SecurityPath:
    """Observed graph path connecting security entities."""
    path_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default"
    source_node_id: str = ""
    target_node_id: str = ""
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    length: int = 0
    classification: str = PathClassification.OBSERVED
    evidence: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.length:
            self.length = len(self.edges)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "tenant_id": self.tenant_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "length": self.length,
            "classification": self.classification,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "evidence": self.evidence
        }


@dataclass
class PathAssessment:
    """Security path evaluation result containing discovered paths and risk signals."""
    assessment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default"
    paths: List[SecurityPath] = field(default_factory=list)
    signals: List[str] = field(default_factory=list)
    risk_level: str = "LOW"
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "tenant_id": self.tenant_id,
            "paths_count": len(self.paths),
            "paths": [p.to_dict() for p in self.paths],
            "signals": self.signals,
            "risk_level": self.risk_level,
            "evidence": self.evidence
        }
