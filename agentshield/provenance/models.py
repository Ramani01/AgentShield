"""
Provenance Data Models and Content Hashing Utilities for AgentShield.
"""

import time
import uuid
import hashlib
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from agentshield.context.models import SourceCategory

def compute_content_hash(content: str) -> str:
    """Computes a deterministic SHA-256 fingerprint of content for integrity checking."""
    if content is None:
        content = ""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

class ProvenanceRecord(BaseModel):
    """Authoritative provenance record tracking source origin and SHA-256 integrity."""

    provenance_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_category: SourceCategory
    source_identifier: str
    origin: str
    parent_provenance_ids: List[str] = Field(default_factory=list)
    timestamp: float = Field(default_factory=time.time)
    content_hash: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": False}
