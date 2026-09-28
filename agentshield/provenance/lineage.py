"""
Action Lineage & Source Provenance Tracking Module.
"""

import uuid
import time
from typing import Dict, Any, List, Optional, Set
from agentshield.context.models import SourceCategory
from agentshield.provenance.models import ProvenanceRecord, compute_content_hash

class ActionLineage:
    """Tracks graph lineage of agent tool calls, sub-agent delegators, and user inputs."""

    def __init__(self, trace_id: str = None):
        self.trace_id = trace_id or str(uuid.uuid4())
        self.nodes: List[Dict[str, Any]] = []

    def record_step(
        self,
        node_type: str,
        name: str,
        inputs: Any,
        outputs: Any = None,
        parent_id: str = None
    ) -> str:
        """Records a step node in the lineage graph."""
        node_id = str(uuid.uuid4())
        node = {
            "node_id": node_id,
            "parent_id": parent_id,
            "trace_id": self.trace_id,
            "timestamp": time.time(),
            "node_type": node_type,  # 'USER_PROMPT', 'AGENT_DECISION', 'TOOL_CALL', 'SUB_AGENT'
            "name": name,
            "inputs": str(inputs),
            "outputs": str(outputs) if outputs else None
        }
        self.nodes.append(node)
        return node_id

    def get_lineage_trace(self) -> Dict[str, Any]:
        """Returns full lineage sequence for current execution trace."""
        return {
            "trace_id": self.trace_id,
            "total_nodes": len(self.nodes),
            "nodes": self.nodes
        }


class ProvenanceTracker:
    """
    Manages source provenance records, multi-parent lineage derivations,
    and SHA-256 content integrity fingerprints.
    """

    def __init__(self):
        self._records: Dict[str, ProvenanceRecord] = {}

    def create_provenance(
        self,
        source_category: SourceCategory,
        source_identifier: str,
        origin: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ProvenanceRecord:
        """Creates a primary source provenance record with a SHA-256 content fingerprint."""
        record = ProvenanceRecord(
            source_category=source_category,
            source_identifier=source_identifier,
            origin=origin,
            parent_provenance_ids=[],
            timestamp=time.time(),
            content_hash=compute_content_hash(content),
            metadata=metadata.copy() if metadata else {}
        )
        self._records[record.provenance_id] = record
        return record

    def derive_from(
        self,
        parent_ids: List[str],
        source_category: SourceCategory,
        source_identifier: str,
        origin: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ProvenanceRecord:
        """Creates a derived provenance record referencing single or multiple parent provenance IDs."""
        valid_parents = [pid for pid in parent_ids if pid in self._records or pid]
        record = ProvenanceRecord(
            source_category=source_category,
            source_identifier=source_identifier,
            origin=origin,
            parent_provenance_ids=valid_parents,
            timestamp=time.time(),
            content_hash=compute_content_hash(content),
            metadata=metadata.copy() if metadata else {}
        )
        self._records[record.provenance_id] = record
        return record

    def get_provenance(self, provenance_id: str) -> Optional[ProvenanceRecord]:
        """Retrieves a provenance record by ID."""
        return self._records.get(provenance_id)

    def get_ancestors(self, provenance_id: str) -> List[ProvenanceRecord]:
        """Recursively traces and returns all ancestor provenance records up to root sources."""
        ancestors: List[ProvenanceRecord] = []
        visited: Set[str] = set()

        def _traverse(pid: str):
            if pid in visited:
                return
            visited.add(pid)
            rec = self.get_provenance(pid)
            if rec:
                ancestors.append(rec)
                for parent_id in rec.parent_provenance_ids:
                    _traverse(parent_id)

        _traverse(provenance_id)
        return ancestors

    def get_lineage(self, provenance_id: str) -> Dict[str, Any]:
        """Returns structured lineage tree for a given provenance record."""
        target = self.get_provenance(provenance_id)
        if not target:
            return {"error": "Provenance record not found", "provenance_id": provenance_id}

        ancestors = self.get_ancestors(provenance_id)
        return {
            "target_provenance_id": provenance_id,
            "target_source_category": target.source_category.value,
            "ancestor_count": len(ancestors),
            "ancestors": [a.model_dump() for a in ancestors]
        }

    def verify_integrity(self, provenance_id: str, current_content: str) -> Dict[str, Any]:
        """
        Verifies content integrity by comparing SHA-256 fingerprint against stored hash.
        Does NOT alter trust level; returns valid boolean status.
        """
        record = self.get_provenance(provenance_id)
        if not record:
            return {
                "valid": False,
                "reason": f"Provenance record {provenance_id} not found",
                "provenance_id": provenance_id
            }

        computed_hash = compute_content_hash(current_content)
        is_valid = (computed_hash == record.content_hash)

        return {
            "valid": is_valid,
            "provenance_id": provenance_id,
            "stored_hash": record.content_hash,
            "computed_hash": computed_hash,
            "reason": "SHA-256 integrity check passed" if is_valid else "SHA-256 content fingerprint mismatch (Content modified)"
        }
