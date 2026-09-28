"""
Tool Governance and Change Review Registry for AgentShield.

Guarantees: AN AGENT MUST NOT SILENTLY OPERATE WITH AN UNEXPECTEDLY CHANGED TOOL DEFINITION OR TOOL SECURITY PROFILE.
Manages tool baselines, detects definition drift, assigns severity & security decisions, and governs baseline approvals.
"""

import time
import re
from typing import Dict, Any, List, Optional, Tuple

from agentshield.context.models import SecurityDecision
from agentshield.security.tool_models import ToolDefinition, ToolBaseline, ToolChangeResult, ChangeSeverity
from agentshield.security.tool_fingerprint import compute_tool_fingerprint, normalize_tool_definition
from agentshield.provenance.lineage import ProvenanceTracker
from agentshield.provenance.logger import AuditLogger

class ToolGovernanceRegistry:
    """
    Local registry and change governance engine for tool definitions.
    Separates tool integrity/change governance from runtime authorization (handled by SecureMCP).
    Does NOT execute real tools or connect to external MCP servers.
    """

    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        self._baselines: Dict[str, ToolBaseline] = {}
        self.audit_logger = audit_logger or AuditLogger()

    def register_baseline(self, tool: ToolDefinition) -> ToolBaseline:
        """Registers or establishes an initial approved baseline for a tool definition."""
        fingerprint = compute_tool_fingerprint(tool)
        baseline = ToolBaseline(
            tool_id=tool.tool_id,
            fingerprint=fingerprint,
            version=tool.version,
            created_at=time.time(),
            updated_at=time.time(),
            provenance_id=tool.provenance_id,
            definition=tool
        )
        self._baselines[tool.tool_id] = baseline

        self.audit_logger.log_event(
            "TOOL_BASELINE_REGISTERED",
            {
                "tool_id": tool.tool_id,
                "version": tool.version,
                "fingerprint": fingerprint,
                "provenance_id": tool.provenance_id
            }
        )
        return baseline

    def get_baseline(self, tool_id: str) -> Optional[ToolBaseline]:
        """Retrieves recorded baseline for a tool ID."""
        return self._baselines.get(tool_id)

    def compare_tool_definition(
        self,
        tool: ToolDefinition,
        expected_tool_id: Optional[str] = None,
        tracker: Optional[ProvenanceTracker] = None
    ) -> ToolChangeResult:
        """
        Compares a current ToolDefinition against its recorded ToolBaseline.
        Detects changes in schemas, capabilities, security metadata, descriptions, versions, provenance, and identity.
        Does NOT automatically overwrite the baseline upon detecting a change.
        """
        new_fingerprint = compute_tool_fingerprint(tool)
        target_id = expected_tool_id or tool.tool_id
        baseline = self.get_baseline(target_id)

        # Handle explicit identity mismatch
        if expected_tool_id and tool.tool_id != expected_tool_id:
            res = ToolChangeResult(
                changed=True,
                tool_id=tool.tool_id,
                old_fingerprint=baseline.fingerprint if baseline else None,
                new_fingerprint=new_fingerprint,
                changed_fields=["tool_id"],
                decision=SecurityDecision.DENY,
                severity=ChangeSeverity.CRITICAL,
                reason=f"Tool identity mismatch: expected '{expected_tool_id}', got '{tool.tool_id}'",
                detected_at=time.time(),
                provenance_id=tool.provenance_id
            )
            self.audit_logger.log_event("TOOL_CHANGE_BLOCKED", res.model_dump())
            return res

        # 1. New Tool without Baseline
        if not baseline:
            res = ToolChangeResult(
                changed=True,
                tool_id=tool.tool_id,
                old_fingerprint=None,
                new_fingerprint=new_fingerprint,
                changed_fields=["tool_id", "initial_registration"],
                decision=SecurityDecision.REVIEW,
                severity=ChangeSeverity.MEDIUM,
                reason="New tool definition without recorded baseline requires review",
                detected_at=time.time(),
                provenance_id=tool.provenance_id
            )
            self.audit_logger.log_event("TOOL_CHANGE_DETECTED", res.model_dump())
            return res

        # 2. Unchanged Tool Definition
        if baseline.fingerprint == new_fingerprint:
            res = ToolChangeResult(
                changed=False,
                tool_id=tool.tool_id,
                old_fingerprint=baseline.fingerprint,
                new_fingerprint=new_fingerprint,
                changed_fields=[],
                decision=SecurityDecision.ALLOW,
                severity=ChangeSeverity.LOW,
                reason="Tool definition unchanged relative to baseline",
                detected_at=time.time(),
                provenance_id=tool.provenance_id
            )
            return res

        # 3. Changed Tool Definition: Inspect Field Differences
        old_def = baseline.definition
        changed_fields: List[str] = []

        if old_def:
            if old_def.tool_id != tool.tool_id:
                changed_fields.append("tool_id")
            if old_def.name != tool.name:
                changed_fields.append("name")
            if old_def.version != tool.version:
                changed_fields.append("version")
            if old_def.description != tool.description:
                changed_fields.append("description")
            if old_def.input_schema != tool.input_schema:
                changed_fields.append("input_schema")
            if old_def.output_schema != tool.output_schema:
                changed_fields.append("output_schema")
            if sorted(old_def.capabilities) != sorted(tool.capabilities):
                changed_fields.append("capabilities")
            if old_def.security_metadata != tool.security_metadata:
                changed_fields.append("security_metadata")
            if old_def.provenance_id != tool.provenance_id:
                changed_fields.append("provenance_id")
        else:
            changed_fields = ["fingerprint"]

        # 4. Classify Severity & Security Decision
        severity = ChangeSeverity.LOW
        decision = SecurityDecision.REVIEW

        if "tool_id" in changed_fields:
            severity = ChangeSeverity.CRITICAL
            decision = SecurityDecision.DENY
        elif "capabilities" in changed_fields or "security_metadata" in changed_fields:
            severity = ChangeSeverity.CRITICAL
            decision = SecurityDecision.REVIEW
        elif "input_schema" in changed_fields or "output_schema" in changed_fields or "name" in changed_fields:
            severity = ChangeSeverity.HIGH
            decision = SecurityDecision.REVIEW
        elif "version" in changed_fields or "provenance_id" in changed_fields:
            severity = ChangeSeverity.MEDIUM
            decision = SecurityDecision.REVIEW
        elif changed_fields == ["description"]:
            severity = ChangeSeverity.LOW
            decision = SecurityDecision.ALLOW  # Description-only change policy default


        res = ToolChangeResult(
            changed=True,
            tool_id=tool.tool_id,
            old_fingerprint=baseline.fingerprint,
            new_fingerprint=new_fingerprint,
            changed_fields=changed_fields,
            decision=decision,
            severity=severity,
            reason=f"Tool definition changed in fields: {', '.join(changed_fields)}",
            detected_at=time.time(),
            provenance_id=tool.provenance_id
        )

        self.audit_logger.log_event(
            "TOOL_CHANGE_BLOCKED" if decision == SecurityDecision.DENY else ("TOOL_CHANGE_REVIEW" if decision == SecurityDecision.REVIEW else "TOOL_CHANGE_ALLOWED"),
            res.model_dump()
        )

        return res

    def approve_tool_change(self, tool_id: str, new_tool: ToolDefinition) -> ToolBaseline:
        """
        Controlled baseline update upon explicit policy or administrative approval.
        Updates the stored ToolBaseline to the new tool definition.
        """
        new_fingerprint = compute_tool_fingerprint(new_tool)
        old_baseline = self._baselines.get(tool_id)

        new_baseline = ToolBaseline(
            tool_id=tool_id,
            fingerprint=new_fingerprint,
            version=new_tool.version,
            created_at=old_baseline.created_at if old_baseline else time.time(),
            updated_at=time.time(),
            provenance_id=new_tool.provenance_id,
            definition=new_tool
        )
        self._baselines[tool_id] = new_baseline

        self.audit_logger.log_event(
            "TOOL_CHANGE_APPROVED",
            {
                "tool_id": tool_id,
                "old_fingerprint": old_baseline.fingerprint if old_baseline else None,
                "new_fingerprint": new_fingerprint,
                "version": new_tool.version
            }
        )

        return new_baseline

    def export_baselines(self) -> Dict[str, ToolBaseline]:
        """Exports a copy of the currently recorded tool baselines."""
        return {k: v.model_copy(deep=True) for k, v in self._baselines.items()}

    def restore_baselines(self, baselines: Dict[str, ToolBaseline]) -> None:
        """Restores tool baselines from a checkpoint state."""
        self._baselines = {k: v.model_copy(deep=True) for k, v in baselines.items()}

