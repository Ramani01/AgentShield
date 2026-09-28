"""
Safe Memory Store with isolated multi-tenant storage and MemorySecurityEngine integration.
"""

import hashlib
import time
from typing import Dict, Any, Optional, List

from agentshield.context.models import UserIdentity, ContextItem, SourceCategory, TrustLevel
from agentshield.provenance.lineage import ProvenanceTracker
from agentshield.provenance.models import compute_content_hash
from agentshield.memory.models import MemoryRecord, MemoryAccessResult
from agentshield.memory.security_engine import MemorySecurityEngine

class SafeMemoryStore:
    """In-memory secure key-value & MemoryRecord store with tenant/user isolation and security engine evaluation."""

    def __init__(self, security_engine: Optional[MemorySecurityEngine] = None):
        self._store: Dict[str, Dict[str, Any]] = {}
        self._records: Dict[str, MemoryRecord] = {}
        self.security_engine = security_engine or MemorySecurityEngine()

    def _get_key_hash(self, tenant_id: str, key: str) -> str:
        raw = f"{tenant_id}:{key}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def set(self, tenant_id: str, key: str, value: Any, owner_id: str = "default_user", provenance_id: Optional[str] = None) -> str:
        """Stores a memory entry bound to a tenant_id with tamper checksum and MemoryRecord representation."""
        store_key = self._get_key_hash(tenant_id, key)
        val_str = str(value)
        checksum = hashlib.sha256(val_str.encode("utf-8")).hexdigest()

        self._store[store_key] = {
            "tenant_id": tenant_id,
            "key": key,
            "value": value,
            "checksum": checksum
        }

        # Also store MemoryRecord representation
        record = MemoryRecord(
            memory_id=key,
            owner_id=owner_id,
            tenant_id=tenant_id,
            content=val_str,
            source_category=SourceCategory.MEMORY,
            trust_level=TrustLevel.UNTRUSTED,
            provenance_id=provenance_id,
            content_hash=checksum,
            metadata={"key": key}
        )
        self._records[store_key] = record
        return checksum

    def set_record(self, record: MemoryRecord) -> str:
        """Stores a security-annotated MemoryRecord directly."""
        store_key = self._get_key_hash(record.tenant_id, record.memory_id)
        if not record.content_hash:
            record.content_hash = compute_content_hash(record.content)

        self._records[store_key] = record
        self._store[store_key] = {
            "tenant_id": record.tenant_id,
            "key": record.memory_id,
            "value": record.content,
            "checksum": record.content_hash
        }
        return record.content_hash

    def get(self, tenant_id: str, key: str) -> Optional[Any]:
        """Retrieves a memory entry after validating tenant ownership and integrity."""
        store_key = self._get_key_hash(tenant_id, key)
        entry = self._store.get(store_key)

        if not entry:
            return None

        # Verify tenant identity match
        if entry["tenant_id"] != tenant_id:
            raise PermissionError("Tenant isolation mismatch!")

        # Verify tamper integrity
        val_str = str(entry["value"])
        computed_checksum = hashlib.sha256(val_str.encode("utf-8")).hexdigest()
        if computed_checksum != entry["checksum"]:
            raise ValueError("Memory corruption/tampering detected!")

        return entry["value"]

    def get_secure_record(
        self,
        identity: Optional[UserIdentity],
        key_or_id: str,
        tracker: Optional[ProvenanceTracker] = None
    ) -> MemoryAccessResult:
        """Retrieves and evaluates a MemoryRecord through MemorySecurityEngine controls."""
        if not identity:
            return self.security_engine.evaluate_memory_access(None, MemoryRecord(owner_id="", tenant_id="", content=""))

        store_key = self._get_key_hash(identity.tenant_id, key_or_id)
        record = self._records.get(store_key)

        if not record:
            # Fallback search across records if key_or_id is a unique memory_id
            for rec in self._records.values():
                if rec.memory_id == key_or_id:
                    record = rec
                    break

        if not record:
            return MemoryAccessResult(
                memory_id=key_or_id,
                authorized=False,
                reason=f"Memory record '{key_or_id}' not found",
                violations=["NOT_FOUND"]
            )

        return self.security_engine.evaluate_memory_access(identity, record, tracker=tracker)

    def retrieve_user_memories(
        self,
        identity: Optional[UserIdentity],
        tracker: Optional[ProvenanceTracker] = None
    ) -> List[ContextItem]:
        """Retrieves all authorized memories for the given UserIdentity as safe ContextItems."""
        if not identity or not identity.user_id or not identity.tenant_id:
            return []

        retrieved_items: List[ContextItem] = []
        for store_key, record in self._records.items():
            if record.tenant_id == identity.tenant_id and (record.owner_id == identity.user_id or "admin" in identity.roles):
                eval_res = self.security_engine.evaluate_memory_access(identity, record, tracker=tracker)
                if eval_res.authorized and eval_res.context_item:
                    retrieved_items.append(eval_res.context_item)

        return retrieved_items

    def delete(self, tenant_id: str, key: str) -> bool:
        """Deletes a memory entry safely."""
        store_key = self._get_key_hash(tenant_id, key)
        deleted = False
        if store_key in self._store:
            del self._store[store_key]
            deleted = True
        if store_key in self._records:
            del self._records[store_key]
            deleted = True
        return deleted
