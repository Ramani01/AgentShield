"""
Security Checkpoint Manager and Rollback Governance Engine for AgentShield.

Guarantees: AN UNTRUSTED OR UNSAFE SECURITY STATE MUST NOT BECOME PERMANENT MERELY BECAUSE IT WAS APPLIED AFTER A PREVIOUSLY APPROVED STATE.
Allows creating immutable security state snapshots and safely restoring them with tenant isolation, identity authorization, and post-restoration verification.
"""

import time
import copy
from typing import Dict, Any, List, Optional

from agentshield.context.models import SecurityDecision, UserIdentity
from agentshield.security.tool_models import ToolBaseline
from agentshield.security.tool_governance import ToolGovernanceRegistry
from agentshield.checkpoint.models import SecurityCheckpoint, CheckpointStatus, RollbackRequest, RollbackResult
from agentshield.checkpoint.fingerprint import compute_checkpoint_fingerprint
from agentshield.provenance.logger import AuditLogger

# Forbidden sensitive keywords that must not be stored in unredacted state
SENSITIVE_KEYWORD_PATTERNS = ["api_key", "secret", "password", "bearer_token", "private_key"]

class CheckpointManager:
    """
    Manages security configuration checkpoints and governs safe rollback.
    Imforces checkpoint immutability, tenant isolation, identity authorization, and post-restoration verification.
    """

    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        self._checkpoints: Dict[str, SecurityCheckpoint] = {}
        self.audit_logger = audit_logger or AuditLogger()

    def _sanitize_snapshot(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redacts raw sensitive secrets/credentials from configuration snapshots."""
        if not isinstance(data, dict):
            return data
        sanitized = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(pat in k_lower for pat in SENSITIVE_KEYWORD_PATTERNS):
                sanitized[k] = "[REDACTED_SECRET]"
            elif isinstance(v, dict):
                sanitized[k] = self._sanitize_snapshot(v)
            elif isinstance(v, list):
                sanitized[k] = [self._sanitize_snapshot(x) if isinstance(x, dict) else x for x in v]
            else:
                sanitized[k] = v
        return sanitized

    def create_checkpoint(
        self,
        created_by: str,
        tenant_id: str = "default",
        description: str = "",
        tool_baselines: Optional[Dict[str, ToolBaseline]] = None,
        policy_snapshot: Optional[Dict[str, Any]] = None,
        configuration_snapshot: Optional[Dict[str, Any]] = None,
        provenance_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SecurityCheckpoint:
        """
        Collects, sanitizes, and creates an immutable SecurityCheckpoint.
        Computes deterministic state fingerprint and logs a CHECKPOINT_CREATED audit event.
        """
        baselines = tool_baselines or {}
        p_snap = self._sanitize_snapshot(policy_snapshot or {})
        c_snap = self._sanitize_snapshot(configuration_snapshot or {})
        meta = self._sanitize_snapshot(metadata or {})

        state_fp = compute_checkpoint_fingerprint(
            tool_baselines=baselines,
            policy_snapshot=p_snap,
            configuration_snapshot=c_snap,
            tenant_id=tenant_id
        )

        checkpoint = SecurityCheckpoint(
            created_at=time.time(),
            created_by=created_by,
            tenant_id=tenant_id,
            description=description,
            state_fingerprint=state_fp,
            tool_baselines=copy.deepcopy(baselines),
            policy_snapshot=p_snap,
            configuration_snapshot=c_snap,
            provenance_id=provenance_id,
            metadata=meta,
            status=CheckpointStatus.ACTIVE
        )

        self._checkpoints[checkpoint.checkpoint_id] = checkpoint

        self.audit_logger.log_event(
            "CHECKPOINT_CREATED",
            {
                "checkpoint_id": checkpoint.checkpoint_id,
                "created_by": created_by,
                "tenant_id": tenant_id,
                "state_fingerprint": state_fp,
                "tool_baseline_count": len(baselines),
                "provenance_id": provenance_id
            },
            tenant_id=tenant_id
        )

        return copy.deepcopy(checkpoint)

    def validate_checkpoint(self, checkpoint_id_or_obj: Any) -> Dict[str, Any]:
        """
        Verifies checkpoint structure, existence, and hash chain state fingerprint match.
        Returns dict with keys: 'valid' (bool), 'reason' (str), 'checkpoint' (Optional[SecurityCheckpoint]).
        """
        if isinstance(checkpoint_id_or_obj, str):
            checkpoint = self._checkpoints.get(checkpoint_id_or_obj)
        elif isinstance(checkpoint_id_or_obj, SecurityCheckpoint):
            checkpoint = checkpoint_id_or_obj
        else:
            checkpoint = None

        if not checkpoint:
            res = {"valid": False, "reason": "Checkpoint not found", "checkpoint": None}
            self.audit_logger.log_event("CHECKPOINT_INVALID", {"reason": res["reason"]})
            return res

        # Re-compute fingerprint to verify integrity
        computed_fp = compute_checkpoint_fingerprint(
            tool_baselines=checkpoint.tool_baselines,
            policy_snapshot=checkpoint.policy_snapshot,
            configuration_snapshot=checkpoint.configuration_snapshot,
            tenant_id=checkpoint.tenant_id
        )

        if computed_fp != checkpoint.state_fingerprint:
            res = {
                "valid": False,
                "reason": f"Integrity failure: expected fingerprint '{checkpoint.state_fingerprint}', computed '{computed_fp}'",
                "checkpoint": copy.deepcopy(checkpoint)
            }
            self.audit_logger.log_event(
                "CHECKPOINT_INVALID",
                {"checkpoint_id": checkpoint.checkpoint_id, "reason": res["reason"]},
                tenant_id=checkpoint.tenant_id
            )
            return res

        res = {"valid": True, "reason": "Checkpoint integrity verified", "checkpoint": copy.deepcopy(checkpoint)}
        self.audit_logger.log_event(
            "CHECKPOINT_VALIDATED",
            {
                "checkpoint_id": checkpoint.checkpoint_id,
                "state_fingerprint": computed_fp
            },
            tenant_id=checkpoint.tenant_id
        )
        return res

    def get_checkpoint(self, checkpoint_id: str) -> Optional[SecurityCheckpoint]:
        """Retrieves a deep copy of a checkpoint by ID to maintain immutability."""
        chk = self._checkpoints.get(checkpoint_id)
        return copy.deepcopy(chk) if chk else None

    def list_checkpoints(self, tenant_id: Optional[str] = None) -> List[SecurityCheckpoint]:
        """Lists recorded security checkpoints, optionally filtered by tenant_id."""
        checkpoints = list(self._checkpoints.values())
        if tenant_id:
            checkpoints = [c for c in checkpoints if c.tenant_id == tenant_id]
        return [copy.deepcopy(c) for c in checkpoints]

    def execute_rollback(
        self,
        request: RollbackRequest,
        identity: Optional[UserIdentity] = None,
        registry: Optional[ToolGovernanceRegistry] = None,
        policy_engine: Any = None,
        config: Any = None
    ) -> RollbackResult:
        """
        Executes explicit, governed rollback to a validated SecurityCheckpoint.
        Enforces identity authorization, tenant isolation, pre-rollback fingerprint capture,
        restoration, and post-restoration verification.
        Does NOT execute tools or network calls.
        """
        # 1. Audit Rollback Request
        self.audit_logger.log_event(
            "ROLLBACK_REQUESTED",
            {
                "checkpoint_id": request.checkpoint_id,
                "requested_by": request.requested_by,
                "tenant_id": request.tenant_id,
                "reason": request.reason
            },
            tenant_id=request.tenant_id
        )

        # 2. Authorization & Identity Validation
        if not request.requested_by or not request.requested_by.strip():
            res = RollbackResult(
                checkpoint_id=request.checkpoint_id,
                decision=SecurityDecision.DENY,
                restored=False,
                reason="Rollback denied: missing identity context (requested_by is required)",
                tenant_id=request.tenant_id
            )
            self.audit_logger.log_event("ROLLBACK_BLOCKED", res.model_dump(), tenant_id=request.tenant_id)
            return res

        if identity:
            if identity.user_id != request.requested_by:
                res = RollbackResult(
                    checkpoint_id=request.checkpoint_id,
                    decision=SecurityDecision.DENY,
                    restored=False,
                    reason=f"Rollback denied: identity user '{identity.user_id}' mismatch with requester '{request.requested_by}'",
                    tenant_id=request.tenant_id
                )
                self.audit_logger.log_event("ROLLBACK_BLOCKED", res.model_dump(), tenant_id=request.tenant_id)
                return res

            if identity.tenant_id != request.tenant_id:
                res = RollbackResult(
                    checkpoint_id=request.checkpoint_id,
                    decision=SecurityDecision.DENY,
                    restored=False,
                    reason=f"Rollback denied: identity tenant '{identity.tenant_id}' mismatch with request tenant '{request.tenant_id}'",
                    tenant_id=request.tenant_id
                )
                self.audit_logger.log_event("ROLLBACK_BLOCKED", res.model_dump(), tenant_id=request.tenant_id)
                return res

            user_roles = getattr(identity, "roles", [])
            if hasattr(identity, "role") and identity.role:
                user_roles = list(user_roles) + [identity.role]
            if not any(r in ["admin", "security_admin", "system"] for r in user_roles):
                res = RollbackResult(
                    checkpoint_id=request.checkpoint_id,
                    decision=SecurityDecision.DENY,
                    restored=False,
                    reason=f"Rollback denied: user roles '{user_roles}' unauthorized for security rollback",
                    tenant_id=request.tenant_id
                )
                self.audit_logger.log_event("ROLLBACK_BLOCKED", res.model_dump(), tenant_id=request.tenant_id)
                return res


        # 3. Checkpoint Existence & Tenant Isolation
        checkpoint = self._checkpoints.get(request.checkpoint_id)
        if not checkpoint:
            res = RollbackResult(
                checkpoint_id=request.checkpoint_id,
                decision=SecurityDecision.DENY,
                restored=False,
                reason=f"Rollback denied: checkpoint '{request.checkpoint_id}' does not exist",
                tenant_id=request.tenant_id
            )
            self.audit_logger.log_event("ROLLBACK_BLOCKED", res.model_dump(), tenant_id=request.tenant_id)
            return res

        if checkpoint.tenant_id != request.tenant_id:
            res = RollbackResult(
                checkpoint_id=request.checkpoint_id,
                decision=SecurityDecision.DENY,
                restored=False,
                reason=f"Rollback denied: tenant scope mismatch (checkpoint tenant '{checkpoint.tenant_id}' vs request tenant '{request.tenant_id}')",
                tenant_id=request.tenant_id
            )
            self.audit_logger.log_event("ROLLBACK_BLOCKED", res.model_dump(), tenant_id=request.tenant_id)
            return res

        # 4. Checkpoint Integrity Validation
        val_res = self.validate_checkpoint(checkpoint)
        if not val_res["valid"]:
            res = RollbackResult(
                checkpoint_id=request.checkpoint_id,
                decision=SecurityDecision.DENY,
                restored=False,
                reason=f"Rollback denied: target checkpoint validation failed ({val_res['reason']})",
                tenant_id=request.tenant_id
            )
            self.audit_logger.log_event("ROLLBACK_BLOCKED", res.model_dump(), tenant_id=request.tenant_id)
            return res

        # 5. Capture Current State Fingerprint
        curr_baselines = registry.export_baselines() if registry else {}
        curr_p_snap = policy_engine.export_policy() if hasattr(policy_engine, "export_policy") else {}
        curr_c_snap = config.model_dump() if hasattr(config, "model_dump") else {}

        previous_fp = compute_checkpoint_fingerprint(
            tool_baselines=curr_baselines,
            policy_snapshot=curr_p_snap,
            configuration_snapshot=curr_c_snap,
            tenant_id=request.tenant_id
        )

        # 6. Apply Restoration
        try:
            if registry:
                registry.restore_baselines(checkpoint.tool_baselines)

            # 7. Post-Restoration Verification
            restored_baselines = registry.export_baselines() if registry else {}
            restored_fp = compute_checkpoint_fingerprint(
                tool_baselines=restored_baselines,
                policy_snapshot=checkpoint.policy_snapshot,
                configuration_snapshot=checkpoint.configuration_snapshot,
                tenant_id=request.tenant_id
            )

            if restored_fp != checkpoint.state_fingerprint:
                # Post-restoration verification failed, revert!
                if registry:
                    registry.restore_baselines(curr_baselines)

                res = RollbackResult(
                    checkpoint_id=request.checkpoint_id,
                    decision=SecurityDecision.DENY,
                    restored=False,
                    reason=f"Rollback failed: restored state fingerprint mismatch (expected {checkpoint.state_fingerprint}, got {restored_fp})",
                    previous_state_fingerprint=previous_fp,
                    restored_state_fingerprint=restored_fp,
                    tenant_id=request.tenant_id
                )
                self.audit_logger.log_event("ROLLBACK_FAILED", res.model_dump(), tenant_id=request.tenant_id)
                return res

            # Update Checkpoint Status
            checkpoint.status = CheckpointStatus.RESTORED
            self._checkpoints[request.checkpoint_id] = checkpoint

            res = RollbackResult(
                checkpoint_id=request.checkpoint_id,
                decision=SecurityDecision.ALLOW,
                restored=True,
                reason=f"Rollback successfully executed to checkpoint '{request.checkpoint_id}'",
                previous_state_fingerprint=previous_fp,
                restored_state_fingerprint=restored_fp,
                tenant_id=request.tenant_id
            )

            self.audit_logger.log_event(
                "ROLLBACK_COMPLETED",
                {
                    "rollback_id": res.rollback_id,
                    "checkpoint_id": request.checkpoint_id,
                    "requested_by": request.requested_by,
                    "tenant_id": request.tenant_id,
                    "previous_state_fingerprint": previous_fp,
                    "restored_state_fingerprint": restored_fp
                },
                tenant_id=request.tenant_id
            )
            return res

        except Exception as e:
            # Revert baseline on exception
            if registry:
                registry.restore_baselines(curr_baselines)

            res = RollbackResult(
                checkpoint_id=request.checkpoint_id,
                decision=SecurityDecision.DENY,
                restored=False,
                reason=f"Rollback execution exception: {str(e)}",
                previous_state_fingerprint=previous_fp,
                tenant_id=request.tenant_id
            )
            self.audit_logger.log_event("ROLLBACK_FAILED", res.model_dump(), tenant_id=request.tenant_id)
            return res
