"""
Central Control Catalog for AgentShield Security Controls.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from agentshield.evaluation.models import ControlCategory
from agentshield.security.tool_models import ChangeSeverity

class ControlDefinition(BaseModel):
    """Stable metadata definition for an implemented AgentShield security control."""

    control_id: str
    name: str
    category: ControlCategory
    description: str
    severity_policy: ChangeSeverity
    required_evidence: List[str]

class ControlCatalog:
    """Central registry of AgentShield's 13 implemented security controls."""

    _CONTROLS: Dict[str, ControlDefinition] = {
        "CONTROL-01": ControlDefinition(
            control_id="CONTROL-01",
            name="Instruction Isolation",
            category=ControlCategory.CONTEXT,
            description="Enforces strict priority boundaries and boundary markers separating trusted system instructions from untrusted data.",
            severity_policy=ChangeSeverity.HIGH,
            required_evidence=["context_items", "priority_order", "boundary_validity"]
        ),
        "CONTROL-02": ControlDefinition(
            control_id="CONTROL-02",
            name="Trust Labeling",
            category=ControlCategory.TRUST,
            description="Assigns explicit TrustLevels and SourceCategories to prevent untrusted data from acting as trusted instructions.",
            severity_policy=ChangeSeverity.HIGH,
            required_evidence=["source_category", "trust_level", "is_instruction_allowed"]
        ),
        "CONTROL-03": ControlDefinition(
            control_id="CONTROL-03",
            name="Prompt Injection Defense",
            category=ControlCategory.INJECTION,
            description="Scans user input and context items for indirect prompt injection, jailbreak attempts, and adversarial patterns.",
            severity_policy=ChangeSeverity.CRITICAL,
            required_evidence=["is_injection", "max_score", "jailbreak_detected"]
        ),
        "CONTROL-04": ControlDefinition(
            control_id="CONTROL-04",
            name="Provenance & Data Lineage",
            category=ControlCategory.PROVENANCE,
            description="Tracks SHA-256 content hashes, origin metadata, and execution lineage trees for end-to-end auditability.",
            severity_policy=ChangeSeverity.MEDIUM,
            required_evidence=["provenance_id", "content_hash", "lineage_trace_valid"]
        ),
        "CONTROL-05": ControlDefinition(
            control_id="CONTROL-05",
            name="Permission-Aware Retrieval",
            category=ControlCategory.RETRIEVED,
            description="Governs RAG retrieval by enforcing tenant and identity permissions before content enters agent context.",
            severity_policy=ChangeSeverity.HIGH,
            required_evidence=["identity", "tenant_id", "retrieval_authorized"]
        ),
        "CONTROL-06": ControlDefinition(
            control_id="CONTROL-06",
            name="Context Integrity",
            category=ControlCategory.INTEGRITY,
            description="Validates context pipelines to guarantee untrusted inputs do not silently escalate to trusted instruction status.",
            severity_policy=ChangeSeverity.CRITICAL,
            required_evidence=["context_items", "integrity_status", "violations"]
        ),
        "CONTROL-07": ControlDefinition(
            control_id="CONTROL-07",
            name="Memory Security",
            category=ControlCategory.MEMORY,
            description="Enforces tenant/user isolation and security filtering on read operations from persistent agent memory.",
            severity_policy=ChangeSeverity.HIGH,
            required_evidence=["memory_id", "user_access_authorized", "tenant_isolation_passed"]
        ),
        "CONTROL-08": ControlDefinition(
            control_id="CONTROL-08",
            name="Memory Write Gates",
            category=ControlCategory.MEMORY_WRITE,
            description="Guards persistent memory writes against untrusted content, secrets, and unauthorized tenant cross-contamination.",
            severity_policy=ChangeSeverity.CRITICAL,
            required_evidence=["memory_write_allowed", "secret_scan_passed", "write_reason"]
        ),
        "CONTROL-09": ControlDefinition(
            control_id="CONTROL-09",
            name="Output & Action Validation",
            category=ControlCategory.OUTPUT,
            description="Inspects generated agent outputs and proposed actions before execution or external release.",
            severity_policy=ChangeSeverity.HIGH,
            required_evidence=["output_valid", "action_valid", "sensitive_data_detected"]
        ),
        "CONTROL-10": ControlDefinition(
            control_id="CONTROL-10",
            name="Egress Control",
            category=ControlCategory.EGRESS,
            description="Validates information leaving the AgentShield security boundary against destination policies and data leakage controls.",
            severity_policy=ChangeSeverity.CRITICAL,
            required_evidence=["destination", "egress_allowed", "data_sensitivity_level"]
        ),
        "CONTROL-11": ControlDefinition(
            control_id="CONTROL-11",
            name="Token / Data Audience Control",
            category=ControlCategory.AUDIENCE,
            description="Restricts data and token claims to authorized recipient audiences, preventing unauthorized cross-audience disclosure.",
            severity_policy=ChangeSeverity.HIGH,
            required_evidence=["target_audience", "audience_valid", "token_scope"]
        ),
        "CONTROL-12": ControlDefinition(
            control_id="CONTROL-12",
            name="Tool Change Detection",
            category=ControlCategory.GOVERNANCE,
            description="Detects definition drift, schema alterations, capability inflation, and identity tampering in agent tool profiles.",
            severity_policy=ChangeSeverity.CRITICAL,
            required_evidence=["tool_id", "fingerprint_match", "changed_fields", "governance_decision"]
        ),
        "CONTROL-13": ControlDefinition(
            control_id="CONTROL-13",
            name="Security Checkpoint & Rollback",
            category=ControlCategory.CHECKPOINT,
            description="Validates security state checkpoints and enforces tenant-isolated, authorized state rollback.",
            severity_policy=ChangeSeverity.HIGH,
            required_evidence=["checkpoint_id", "checkpoint_integrity_valid", "rollback_decision"]
        )
    }

    @classmethod
    def get_control(cls, control_id: str) -> Optional[ControlDefinition]:
        """Retrieves control definition by stable ID."""
        return cls._CONTROLS.get(control_id)

    @classmethod
    def list_controls(cls) -> List[ControlDefinition]:
        """Lists all 13 registered security control definitions."""
        return list(cls._CONTROLS.values())
