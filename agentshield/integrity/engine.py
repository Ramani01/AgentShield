"""
Runtime Integrity Engine for Phase 23 Runtime Environment Integrity.
Monitors runtime security state against approved baselines to detect drift or tamper.
"""

import sys
import platform
import hashlib
import json
from typing import Dict, Any, Optional, List
from agentshield.context.models import SecurityDecision
from agentshield.provenance.logger import AuditLogger
from agentshield.capabilities.models import AgentCapabilityProfile
from agentshield.communication.models import CommunicationPolicyRule
from agentshield.integrity.models import (
    IntegrityState,
    RuntimeIntegrityBaseline,
    RuntimeStateSnapshot,
    IntegrityCheckResult,
    compute_canonical_hash
)


class RuntimeIntegrityEngine:
    """
    Central evaluator detecting configuration, capability, communication policy,
    or tool definition drift against authoritative baseline snapshots.
    """

    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        capability_engine: Optional[Any] = None,
        comm_engine: Optional[Any] = None,
        tool_registry: Optional[Any] = None
    ):
        self.audit_logger = audit_logger or AuditLogger()
        self.capability_engine = capability_engine
        self.comm_engine = comm_engine
        self.tool_registry = tool_registry
        self._baselines: Dict[str, RuntimeIntegrityBaseline] = {}

    @staticmethod
    def get_safe_env_metadata() -> Dict[str, Any]:
        """Collects non-sensitive local runtime environment metadata."""
        return {
            "python_version": sys.version.split()[0],
            "platform": platform.system(),
            "agentshield_version": "0.2.2"
        }

    @staticmethod
    def compute_capability_fingerprint(profile: Optional[AgentCapabilityProfile]) -> str:
        """Computes SHA-256 fingerprint for an agent's capability profile."""
        if not profile:
            return "no_capability_profile"
        granted = sorted([c.value for c, g in profile.grants.items() if g.granted])
        raw = json.dumps({"agent_id": profile.agent_id, "granted": granted}, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def compute_comm_policy_fingerprint(rules: Optional[List[CommunicationPolicyRule]]) -> str:
        """Computes SHA-256 fingerprint for communication policy rules."""
        if not rules:
            return "no_comm_rules"
        serialized = []
        for r in sorted(rules, key=lambda x: x.rule_id):
            serialized.append({
                "rule_id": r.rule_id,
                "source_type": r.source_type.value if r.source_type else None,
                "destination_type": r.destination_type.value if r.destination_type else None,
                "comm_type": r.comm_type.value if r.comm_type else None,
                "decision": r.decision.value
            })
        raw = json.dumps(serialized, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def compute_tool_fingerprints(tool_defs: Optional[List[Any]]) -> Dict[str, str]:
        """Computes dictionary of tool_name -> SHA-256 fingerprint."""
        if not tool_defs:
            return {}
        fingerprints = {}
        for t in tool_defs:
            name = getattr(t, "name", str(t))
            if hasattr(t, "input_schema") and isinstance(getattr(t, "input_schema"), dict):
                schema = getattr(t, "input_schema")
            elif hasattr(t, "parameters") and isinstance(getattr(t, "parameters"), dict):
                schema = getattr(t, "parameters")
            elif hasattr(t, "model_dump"):
                schema = t.model_dump()
            else:
                schema = str(t)
            raw = json.dumps({"name": name, "schema": schema}, sort_keys=True)
            fingerprints[name] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return fingerprints

    def register_baseline(self, baseline: RuntimeIntegrityBaseline) -> None:
        """Registers an authoritative, approved runtime integrity baseline."""
        key = f"{baseline.tenant_id}:{baseline.agent_id}"
        self._baselines[key] = baseline
        self.audit_logger.log_event(
            "RUNTIME_BASELINE_CREATED",
            {
                "baseline_id": baseline.baseline_id,
                "agent_id": baseline.agent_id,
                "tenant_id": baseline.tenant_id,
                "baseline_hash": baseline.baseline_hash
            },
            tenant_id=baseline.tenant_id
        )

    def create_baseline(
        self,
        agent_id: str = "default_agent",
        tenant_id: str = "default",
        capability_profile: Optional[AgentCapabilityProfile] = None,
        comm_rules: Optional[List[CommunicationPolicyRule]] = None,
        tool_definitions: Optional[List[Any]] = None,
        env_metadata: Optional[Dict[str, Any]] = None
    ) -> RuntimeIntegrityBaseline:
        """Helper to construct and register a new RuntimeIntegrityBaseline."""
        cap_fp = self.compute_capability_fingerprint(capability_profile)
        comm_fp = self.compute_comm_policy_fingerprint(comm_rules)
        tool_fps = self.compute_tool_fingerprints(tool_definitions)
        env_meta = env_metadata if env_metadata is not None else self.get_safe_env_metadata()

        baseline = RuntimeIntegrityBaseline(
            agent_id=agent_id,
            tenant_id=tenant_id,
            capability_fingerprint=cap_fp,
            comm_policy_fingerprint=comm_fp,
            tool_fingerprints=tool_fps,
            env_metadata=env_meta
        )
        self.register_baseline(baseline)
        return baseline

    def capture_snapshot(
        self,
        agent_id: str = "default_agent",
        tenant_id: str = "default",
        capability_profile: Optional[AgentCapabilityProfile] = None,
        comm_rules: Optional[List[CommunicationPolicyRule]] = None,
        tool_definitions: Optional[List[Any]] = None,
        env_metadata: Optional[Dict[str, Any]] = None
    ) -> RuntimeStateSnapshot:
        """Captures a snapshot of the current active runtime security state."""
        # Auto-fetch from engines if parameters not provided
        if capability_profile is None and self.capability_engine:
            capability_profile = self.capability_engine.get_profile(agent_id=agent_id, tenant_id=tenant_id)
        if comm_rules is None and self.comm_engine:
            comm_rules = getattr(self.comm_engine, "_rules", [])

        cap_fp = self.compute_capability_fingerprint(capability_profile)
        comm_fp = self.compute_comm_policy_fingerprint(comm_rules)
        tool_fps = self.compute_tool_fingerprints(tool_definitions)
        env_meta = env_metadata if env_metadata is not None else self.get_safe_env_metadata()

        return RuntimeStateSnapshot(
            agent_id=agent_id,
            tenant_id=tenant_id,
            capability_fingerprint=cap_fp,
            comm_policy_fingerprint=comm_fp,
            tool_fingerprints=tool_fps,
            env_metadata=env_meta
        )

    def evaluate_integrity(
        self,
        agent_id: str = "default_agent",
        tenant_id: str = "default",
        current_snapshot: Optional[RuntimeStateSnapshot] = None
    ) -> IntegrityCheckResult:
        """
        Evaluates current active runtime security snapshot against registered baseline.
        Returns IntegrityCheckResult with decision (ALLOW, DENY, REVIEW, ISOLATE).
        """
        key = f"{tenant_id}:{agent_id}"
        baseline = self._baselines.get(key)

        # 1. Missing Baseline
        if not baseline:
            self.audit_logger.log_event(
                "RUNTIME_BASELINE_MISMATCH",
                {
                    "agent_id": agent_id,
                    "tenant_id": tenant_id,
                    "reason": "No approved runtime integrity baseline registered"
                },
                tenant_id=tenant_id
            )
            self.audit_logger.log_event(
                "RUNTIME_INTEGRITY_BLOCKED",
                {
                    "agent_id": agent_id,
                    "tenant_id": tenant_id,
                    "reason": "Missing integrity baseline"
                },
                tenant_id=tenant_id
            )
            return IntegrityCheckResult(
                state=IntegrityState.UNKNOWN,
                decision=SecurityDecision.DENY,
                allowed=False,
                reason="No registered integrity baseline found for agent (Fail-closed)",
                violations=["MISSING_INTEGRITY_BASELINE"]
            )

        snapshot = current_snapshot or self.capture_snapshot(agent_id=agent_id, tenant_id=tenant_id)
        drift_details = {}
        violations = []

        # 2. Check Capability Fingerprint Drift
        if baseline.capability_fingerprint != snapshot.capability_fingerprint:
            drift_details["capability_drift"] = {
                "expected": baseline.capability_fingerprint,
                "actual": snapshot.capability_fingerprint
            }
            violations.append("CAPABILITY_DRIFT_DETECTED")

        # 3. Check Communication Policy Fingerprint Drift
        if baseline.comm_policy_fingerprint != snapshot.comm_policy_fingerprint:
            drift_details["comm_policy_drift"] = {
                "expected": baseline.comm_policy_fingerprint,
                "actual": snapshot.comm_policy_fingerprint
            }
            violations.append("COMMUNICATION_POLICY_DRIFT")

        # 4. Check Tool Fingerprints Drift
        if baseline.tool_fingerprints != snapshot.tool_fingerprints:
            drift_details["tool_fingerprint_drift"] = {
                "expected": baseline.tool_fingerprints,
                "actual": snapshot.tool_fingerprints
            }
            violations.append("TOOL_FINGERPRINT_DRIFT")

        # 5. Check Environment Metadata Drift
        if baseline.env_metadata != snapshot.env_metadata:
            drift_details["env_metadata_drift"] = {
                "expected": baseline.env_metadata,
                "actual": snapshot.env_metadata
            }
            violations.append("ENV_METADATA_DRIFT")

        # 6. Evaluate Decision based on Drift
        if not violations:
            self.audit_logger.log_event(
                "RUNTIME_INTEGRITY_VALID",
                {
                    "agent_id": agent_id,
                    "tenant_id": tenant_id,
                    "baseline_hash": baseline.baseline_hash
                },
                tenant_id=tenant_id
            )
            return IntegrityCheckResult(
                state=IntegrityState.VALID,
                decision=SecurityDecision.ALLOW,
                allowed=True,
                reason="Runtime environment state matches approved security baseline",
                violations=[]
            )

        # Severe Drift (Capability or Communication Policy changed) -> DENY
        if "CAPABILITY_DRIFT_DETECTED" in violations or "COMMUNICATION_POLICY_DRIFT" in violations:
            self.audit_logger.log_event(
                "RUNTIME_INTEGRITY_BLOCKED",
                {
                    "agent_id": agent_id,
                    "tenant_id": tenant_id,
                    "violations": violations,
                    "reason": "Security boundary capability/policy drift detected"
                },
                tenant_id=tenant_id
            )
            return IntegrityCheckResult(
                state=IntegrityState.DRIFTED,
                decision=SecurityDecision.DENY,
                allowed=False,
                reason="Severe runtime security boundary drift detected (Capability/Policy change)",
                drift_details=drift_details,
                violations=violations
            )

        # Medium Drift (Tool or Env Metadata changed) -> REVIEW
        self.audit_logger.log_event(
            "RUNTIME_INTEGRITY_REVIEW",
            {
                "agent_id": agent_id,
                "tenant_id": tenant_id,
                "violations": violations,
                "reason": "Runtime configuration/tool drift requires review"
            },
            tenant_id=tenant_id
        )
        return IntegrityCheckResult(
            state=IntegrityState.REVIEW,
            decision=SecurityDecision.REVIEW,
            allowed=False,
            reason="Runtime configuration or tool fingerprint drift detected; security review required",
            drift_details=drift_details,
            violations=violations
        )
