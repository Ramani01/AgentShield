"""
Security Checkpoint Fingerprinting and Canonicalization for AgentShield.
"""

import json
import re
from typing import Dict, Any, Optional
from agentshield.security.tool_models import ToolBaseline
from agentshield.security.tool_fingerprint import _normalize_obj
from agentshield.provenance.models import compute_content_hash

def compute_checkpoint_fingerprint(
    tool_baselines: Dict[str, ToolBaseline],
    policy_snapshot: Dict[str, Any],
    configuration_snapshot: Dict[str, Any],
    tenant_id: str = "default"
) -> str:
    """
    Computes a deterministic SHA-256 state fingerprint for a security checkpoint payload.
    Canonicalizes tool baselines, policy snapshot, configuration snapshot, and tenant ID.
    
    IMPORTANT: CHECKPOINT FINGERPRINT != TRUST.
    Valid fingerprint proves representation has not changed, NOT that state is safe.
    """
    raw_baselines = {}
    for tid, b in sorted(tool_baselines.items()):
        raw_baselines[tid] = {
            "tool_id": b.tool_id,
            "fingerprint": b.fingerprint,
            "version": b.version,
            "provenance_id": b.provenance_id or ""
        }

    raw_state = {
        "tenant_id": tenant_id,
        "tool_baselines": raw_baselines,
        "policy_snapshot": policy_snapshot,
        "configuration_snapshot": configuration_snapshot
    }

    normalized = _normalize_obj(raw_state)
    serialized = json.dumps(normalized, sort_keys=True)
    return compute_content_hash(serialized)
