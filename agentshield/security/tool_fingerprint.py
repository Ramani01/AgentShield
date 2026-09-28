"""
Tool Fingerprinting and Deterministic Normalization for AgentShield.
"""

import json
import re
from typing import Dict, Any, List
from agentshield.security.tool_models import ToolDefinition
from agentshield.provenance.models import compute_content_hash

def _normalize_obj(obj: Any) -> Any:
    """Recursively normalizes dictionaries, lists, and strings for deterministic JSON serialization."""
    if isinstance(obj, dict):
        return {k: _normalize_obj(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        normalized_list = [_normalize_obj(x) for x in obj]
        # Sort lists of primitive values for deterministic order (e.g. capabilities)
        if all(isinstance(x, (str, int, float, bool)) for x in normalized_list):
            return sorted(normalized_list, key=lambda x: str(x))
        return normalized_list
    elif isinstance(obj, str):
        # Normalize whitespace in string descriptions/names
        return re.sub(r"\s+", " ", obj.strip())
    else:
        return obj

def normalize_tool_definition(tool: ToolDefinition) -> Dict[str, Any]:
    """
    Deterministically normalizes a ToolDefinition prior to SHA-256 fingerprinting.
    Ensures key order, whitespace, and list ordering differences do not cause false change alerts,
    while preserving all security-relevant fields.
    """
    raw_dict = {
        "tool_id": tool.tool_id,
        "name": tool.name,
        "version": tool.version,
        "description": tool.description,
        "input_schema": tool.input_schema,
        "output_schema": tool.output_schema,
        "capabilities": tool.capabilities,
        "security_metadata": tool.security_metadata,
        "provenance_id": tool.provenance_id or ""
    }
    return _normalize_obj(raw_dict)

def compute_tool_fingerprint(tool: ToolDefinition) -> str:
    """
    Computes a deterministic SHA-256 fingerprint for a ToolDefinition.
    Equivalent tool definitions with different key ordering or formatting produce identical fingerprints.
    """
    normalized = normalize_tool_definition(tool)
    serialized = json.dumps(normalized, sort_keys=True)
    return compute_content_hash(serialized)
