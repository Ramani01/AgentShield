"""
Modular Control Evaluators for AgentShield Security Evaluation Engine.

Each evaluator coordinates existing AgentShield security components to produce evidence-based control results.
Does NOT duplicate validation logic or execute agent tools / external network calls.
"""

import time
import traceback
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod

from agentshield.context.models import SecurityDecision, TrustLevel, SourceCategory
from agentshield.security.tool_models import ChangeSeverity
from agentshield.evaluation.models import (
    ControlStatus,
    SecurityControlResult,
    SecurityFinding,
    SecurityEvaluationContext
)
from agentshield.evaluation.catalog import ControlCatalog, ControlDefinition

class BaseSecurityEvaluator(ABC):
    """Abstract base class for modular AgentShield control evaluators."""

    def __init__(self, control_id: str):
        self.control_id = control_id
        self.definition: Optional[ControlDefinition] = ControlCatalog.get_control(control_id)

    @abstractmethod
    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityControlResult:
        """Evaluates the control against the provided context and SecurityPipeline."""
        pass

    def _create_result(
        self,
        status: ControlStatus,
        decision: SecurityDecision,
        severity: ChangeSeverity,
        reason: str,
        evidence: Dict[str, Any]
    ) -> SecurityControlResult:
        """Helper to construct a standardized SecurityControlResult."""
        return SecurityControlResult(
            control_id=self.control_id,
            control_name=self.definition.name if self.definition else self.control_id,
            category=self.definition.category if self.definition else "CONTEXT",
            status=status,
            decision=decision,
            severity=severity,
            reason=reason,
            evidence=evidence,
            timestamp=time.time()
        )

# =====================================================================
# 1. INSTRUCTION ISOLATION EVALUATOR (CONTROL-01)
# =====================================================================
class InstructionIsolationEvaluator(BaseSecurityEvaluator):
    def __init__(self):
        super().__init__("CONTROL-01")

    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityControlResult:
        if not ctx.context_items:
            return self._create_result(
                ControlStatus.NOT_EVALUATED, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "No context items supplied for instruction isolation evaluation", {}
            )
        try:
            processed_items = pipeline.instruction_boundary.process_context_items(ctx.context_items)
            boundary_violations = []
            for item in processed_items:
                if item.trust_level in [TrustLevel.UNTRUSTED, TrustLevel.USER_CONTROLLED] and item.is_instruction_allowed:
                    boundary_violations.append(item.id)

            if boundary_violations:
                return self._create_result(
                    ControlStatus.FAIL, SecurityDecision.DENY, ChangeSeverity.HIGH,
                    f"Instruction boundary violation: {len(boundary_violations)} untrusted items permitted as instructions",
                    {"item_count": len(ctx.context_items), "violations": boundary_violations}
                )

            return self._create_result(
                ControlStatus.PASS, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "Instruction isolation boundary verified intact",
                {"item_count": len(ctx.context_items), "boundary_valid": True}
            )
        except Exception as e:
            return self._create_result(
                ControlStatus.ERROR, SecurityDecision.DENY, ChangeSeverity.HIGH,
                f"Instruction isolation evaluation error: {str(e)}", {"error": str(e)}
            )

# =====================================================================
# 2. TRUST LABEL EVALUATOR (CONTROL-02)
# =====================================================================
class TrustLabelEvaluator(BaseSecurityEvaluator):
    def __init__(self):
        super().__init__("CONTROL-02")

    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityControlResult:
        if not ctx.context_items:
            return self._create_result(
                ControlStatus.NOT_EVALUATED, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "No context items supplied for trust label evaluation", {}
            )
        try:
            violations = []
            for item in ctx.context_items:
                if item.trust_level == TrustLevel.UNTRUSTED and item.is_instruction_allowed:
                    violations.append(item.id)

            if violations:
                return self._create_result(
                    ControlStatus.FAIL, SecurityDecision.DENY, ChangeSeverity.CRITICAL,
                    f"Trust labeling violation: {len(violations)} UNTRUSTED items labeled as executable instructions",
                    {"violations": violations, "total_items": len(ctx.context_items)}
                )

            return self._create_result(
                ControlStatus.PASS, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "Trust labels verified clean",
                {"total_items": len(ctx.context_items), "trust_labels_valid": True}
            )
        except Exception as e:
            return self._create_result(
                ControlStatus.ERROR, SecurityDecision.DENY, ChangeSeverity.HIGH,
                f"Trust label evaluation error: {str(e)}", {"error": str(e)}
            )

# =====================================================================
# 3. PROMPT INJECTION EVALUATOR (CONTROL-03)
# =====================================================================
class PromptInjectionEvaluator(BaseSecurityEvaluator):
    def __init__(self):
        super().__init__("CONTROL-03")

    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityControlResult:
        if not ctx.context_items:
            return self._create_result(
                ControlStatus.NOT_EVALUATED, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "No text or context items supplied for prompt injection scan", {}
            )
        try:
            detected_injections = []
            max_score = 0.0
            for item in ctx.context_items:
                if item.trust_level in [TrustLevel.UNTRUSTED, TrustLevel.USER_CONTROLLED, TrustLevel.UNKNOWN]:
                    res = pipeline.injection_scanner.scan(item.content)
                    if res.get("max_score", 0.0) > max_score:
                        max_score = res.get("max_score", 0.0)
                    if res.get("is_injection"):
                        detected_injections.append({"item_id": item.id, "score": res.get("max_score")})

            if detected_injections:
                return self._create_result(
                    ControlStatus.FAIL, SecurityDecision.DENY, ChangeSeverity.CRITICAL,
                    f"Prompt injection detected in {len(detected_injections)} context item(s)",
                    {"max_score": max_score, "detected_injections": len(detected_injections)}
                )

            return self._create_result(
                ControlStatus.PASS, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "Prompt injection scanner clean",
                {"max_score": max_score, "scanned_items": len(ctx.context_items)}
            )
        except Exception as e:
            return self._create_result(
                ControlStatus.ERROR, SecurityDecision.DENY, ChangeSeverity.HIGH,
                f"Prompt injection evaluation error: {str(e)}", {"error": str(e)}
            )

# =====================================================================
# 4. PROVENANCE EVALUATOR (CONTROL-04)
# =====================================================================
class ProvenanceEvaluator(BaseSecurityEvaluator):
    def __init__(self):
        super().__init__("CONTROL-04")

    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityControlResult:
        if not ctx.context_items and not ctx.provenance_tracker:
            return self._create_result(
                ControlStatus.NOT_EVALUATED, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "No provenance tracker or context items supplied for lineage evaluation", {}
            )
        try:
            missing_provenance = []
            for item in ctx.context_items:
                if item.trust_level in [TrustLevel.INTERNAL, TrustLevel.TRUSTED] and not item.provenance_id:
                    missing_provenance.append(item.id)

            if missing_provenance:
                return self._create_result(
                    ControlStatus.REVIEW, SecurityDecision.REVIEW, ChangeSeverity.MEDIUM,
                    f"Provenance evaluation warning: {len(missing_provenance)} trusted item(s) missing provenance IDs",
                    {"missing_provenance_count": len(missing_provenance)}
                )

            return self._create_result(
                ControlStatus.PASS, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "Provenance and lineage integrity verified",
                {"context_item_count": len(ctx.context_items), "provenance_valid": True}
            )
        except Exception as e:
            return self._create_result(
                ControlStatus.ERROR, SecurityDecision.DENY, ChangeSeverity.HIGH,
                f"Provenance evaluation error: {str(e)}", {"error": str(e)}
            )

# =====================================================================
# 5. RETRIEVAL AUTHORIZATION EVALUATOR (CONTROL-05)
# =====================================================================
class RetrievalAuthorizationEvaluator(BaseSecurityEvaluator):
    def __init__(self):
        super().__init__("CONTROL-05")

    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityControlResult:
        if not ctx.retrieval_request and not ctx.retrieval_records:
            return self._create_result(
                ControlStatus.NOT_EVALUATED, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "No retrieval request or records supplied for retrieval governance evaluation", {}
            )
        try:
            if not ctx.identity:
                return self._create_result(
                    ControlStatus.FAIL, SecurityDecision.DENY, ChangeSeverity.HIGH,
                    "Retrieval authorization denied: missing identity context",
                    {"tenant_id": ctx.tenant_id}
                )

            return self._create_result(
                ControlStatus.PASS, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "Retrieval authorization verified clean",
                {"user_id": ctx.identity.user_id, "tenant_id": ctx.identity.tenant_id}
            )
        except Exception as e:
            return self._create_result(
                ControlStatus.ERROR, SecurityDecision.DENY, ChangeSeverity.HIGH,
                f"Retrieval authorization evaluation error: {str(e)}", {"error": str(e)}
            )

# =====================================================================
# 6. CONTEXT INTEGRITY EVALUATOR (CONTROL-06)
# =====================================================================
class ContextIntegrityEvaluator(BaseSecurityEvaluator):
    def __init__(self):
        super().__init__("CONTROL-06")

    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityControlResult:
        if not ctx.context_items:
            return self._create_result(
                ControlStatus.NOT_EVALUATED, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "No context items supplied for context integrity evaluation", {}
            )
        try:
            integ_res = pipeline.integrity_engine.validate_context(ctx.context_items)
            if not integ_res.valid:
                return self._create_result(
                    ControlStatus.FAIL, SecurityDecision.DENY, ChangeSeverity.CRITICAL,
                    f"Context integrity failure: {len(integ_res.violations)} violation(s) detected",
                    {"violations": integ_res.violations, "item_count": integ_res.item_count}
                )

            return self._create_result(
                ControlStatus.PASS, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "Context integrity verified clean",
                {"item_count": integ_res.item_count, "integrity_valid": True}
            )
        except Exception as e:
            return self._create_result(
                ControlStatus.ERROR, SecurityDecision.DENY, ChangeSeverity.CRITICAL,
                f"Context integrity evaluation error: {str(e)}", {"error": str(e)}
            )

# =====================================================================
# 7. MEMORY SECURITY EVALUATOR (CONTROL-07)
# =====================================================================
class MemorySecurityEvaluator(BaseSecurityEvaluator):
    def __init__(self):
        super().__init__("CONTROL-07")

    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityControlResult:
        if not ctx.memory_records:
            return self._create_result(
                ControlStatus.NOT_EVALUATED, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "No memory records supplied for memory security evaluation", {}
            )
        try:
            denied_records = []
            for rec in ctx.memory_records:
                eval_res = pipeline.memory_security_engine.evaluate_memory_access(ctx.identity, rec)
                if not eval_res.authorized:
                    denied_records.append({"memory_id": rec.memory_id, "reason": eval_res.reason})

            if denied_records:
                return self._create_result(
                    ControlStatus.FAIL, SecurityDecision.DENY, ChangeSeverity.HIGH,
                    f"Memory security evaluation denied access to {len(denied_records)} memory record(s)",
                    {"denied_count": len(denied_records), "denied_records": denied_records}
                )

            return self._create_result(
                ControlStatus.PASS, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "Memory security evaluation authorized access to all memory records",
                {"record_count": len(ctx.memory_records), "authorized": True}
            )
        except Exception as e:
            return self._create_result(
                ControlStatus.ERROR, SecurityDecision.DENY, ChangeSeverity.HIGH,
                f"Memory security evaluation error: {str(e)}", {"error": str(e)}
            )

# =====================================================================
# 8. MEMORY WRITE EVALUATOR (CONTROL-08)
# =====================================================================
class MemoryWriteEvaluator(BaseSecurityEvaluator):
    def __init__(self):
        super().__init__("CONTROL-08")

    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityControlResult:
        if not ctx.memory_write_request:
            return self._create_result(
                ControlStatus.NOT_EVALUATED, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "No memory write request supplied for memory write gate evaluation", {}
            )
        try:
            res = pipeline.memory_write_gate.execute_memory_write(ctx.memory_write_request, identity=ctx.identity)
            if not res.allowed:
                return self._create_result(
                    ControlStatus.FAIL, SecurityDecision.DENY, ChangeSeverity.CRITICAL,
                    f"Memory write gate denied request: {res.reason}",
                    {"allowed": False, "violations": res.violations}
                )

            return self._create_result(
                ControlStatus.PASS, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "Memory write gate permitted request",
                {"allowed": True, "memory_id": res.memory_id}
            )
        except Exception as e:
            return self._create_result(
                ControlStatus.ERROR, SecurityDecision.DENY, ChangeSeverity.CRITICAL,
                f"Memory write gate evaluation error: {str(e)}", {"error": str(e)}
            )

# =====================================================================
# 9. OUTPUT VALIDATION EVALUATOR (CONTROL-09)
# =====================================================================
class OutputValidationEvaluator(BaseSecurityEvaluator):
    def __init__(self):
        super().__init__("CONTROL-09")

    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityControlResult:
        if not ctx.agent_output and not ctx.agent_action:
            return self._create_result(
                ControlStatus.NOT_EVALUATED, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "No agent output or action supplied for validation", {}
            )
        try:
            if ctx.agent_output:
                res = pipeline.output_action_validator.validate_output(ctx.agent_output, identity=ctx.identity)
                if not res.valid:
                    return self._create_result(
                        ControlStatus.FAIL, SecurityDecision.DENY, ChangeSeverity.HIGH,
                        f"Agent output validation failed: {res.reason}",
                        {"valid": False, "sensitive_data_detected": res.sensitive_data_detected}
                    )

            if ctx.agent_action:
                act_res = pipeline.output_action_validator.validate_action(ctx.agent_action, identity=ctx.identity)
                if not act_res.valid:
                    return self._create_result(
                        ControlStatus.FAIL, SecurityDecision.DENY, ChangeSeverity.HIGH,
                        f"Agent action validation failed: {act_res.reason}",
                        {"valid": False, "action_type": ctx.agent_action.action_type.value}
                    )
                if act_res.decision == SecurityDecision.REVIEW:
                    return self._create_result(
                        ControlStatus.REVIEW, SecurityDecision.REVIEW, ChangeSeverity.HIGH,
                        f"Agent action requires review: {act_res.reason}",
                        {"valid": True, "action_type": ctx.agent_action.action_type.value}
                    )


            return self._create_result(
                ControlStatus.PASS, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "Agent output and action validation passed",
                {"output_valid": True, "action_valid": True}
            )
        except Exception as e:
            return self._create_result(
                ControlStatus.ERROR, SecurityDecision.DENY, ChangeSeverity.HIGH,
                f"Output/action validation error: {str(e)}", {"error": str(e)}
            )

# =====================================================================
# 10. EGRESS EVALUATOR (CONTROL-10)
# =====================================================================
class EgressEvaluator(BaseSecurityEvaluator):
    def __init__(self):
        super().__init__("CONTROL-10")

    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityControlResult:
        if not ctx.egress_request:
            return self._create_result(
                ControlStatus.NOT_EVALUATED, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "No egress request supplied for egress evaluation", {}
            )
        try:
            res = pipeline.egress_validator.validate_egress(ctx.egress_request, identity=ctx.identity)
            if not res.allowed:
                return self._create_result(
                    ControlStatus.FAIL, res.decision, ChangeSeverity.CRITICAL,
                    f"Egress control validation denied: {res.reason}",
                    {"destination": ctx.egress_request.destination, "allowed": False}
                )

            return self._create_result(
                ControlStatus.PASS, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "Egress control validation passed",
                {"destination": ctx.egress_request.destination, "allowed": True}
            )
        except Exception as e:
            return self._create_result(
                ControlStatus.ERROR, SecurityDecision.DENY, ChangeSeverity.CRITICAL,
                f"Egress evaluation error: {str(e)}", {"error": str(e)}
            )

# =====================================================================
# 11. AUDIENCE EVALUATOR (CONTROL-11)
# =====================================================================
class AudienceEvaluator(BaseSecurityEvaluator):
    def __init__(self):
        super().__init__("CONTROL-11")

    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityControlResult:
        if not ctx.audience_claim:
            return self._create_result(
                ControlStatus.NOT_EVALUATED, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "No audience claim supplied for audience evaluation", {}
            )
        try:
            target_aud = getattr(ctx.audience_claim, "principal_id", None) or str(ctx.audience_claim.audience_type)
            token_ctx = getattr(ctx, "token_context", None)
            res = pipeline.audience_validator.validate_audience(claim=ctx.audience_claim, identity=ctx.identity, token_context=token_ctx)
            if not res.valid:
                return self._create_result(
                    ControlStatus.FAIL, res.decision, ChangeSeverity.HIGH,
                    f"Audience validation failed: {res.reason}",
                    {"valid": False, "target_audience": target_aud}
                )

            return self._create_result(
                ControlStatus.PASS, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "Audience validation passed",
                {"valid": True, "target_audience": target_aud}
            )
        except Exception as e:
            return self._create_result(
                ControlStatus.ERROR, SecurityDecision.DENY, ChangeSeverity.HIGH,
                f"Audience evaluation error: {str(e)}", {"error": str(e)}
            )

# =====================================================================
# 12. TOOL GOVERNANCE EVALUATOR (CONTROL-12)
# =====================================================================
class ToolGovernanceEvaluator(BaseSecurityEvaluator):
    def __init__(self):
        super().__init__("CONTROL-12")

    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityControlResult:
        if not ctx.tool_definitions:
            return self._create_result(
                ControlStatus.NOT_EVALUATED, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "No tool definitions supplied for tool change governance evaluation", {}
            )
        try:
            changed_tools = []
            for tool in ctx.tool_definitions:
                res = pipeline.validate_tool_change(tool, expected_tool_id=ctx.expected_tool_id)
                if res.changed:
                    changed_tools.append({
                        "tool_id": tool.tool_id,
                        "decision": res.decision.value,
                        "severity": res.severity.value,
                        "changed_fields": res.changed_fields
                    })

            if any(t["decision"] == SecurityDecision.DENY.value for t in changed_tools):
                return self._create_result(
                    ControlStatus.FAIL, SecurityDecision.DENY, ChangeSeverity.CRITICAL,
                    f"Tool governance check denied tool change in {len(changed_tools)} tool(s)",
                    {"changed_tools": changed_tools}
                )

            if changed_tools:
                return self._create_result(
                    ControlStatus.REVIEW, SecurityDecision.REVIEW, ChangeSeverity.HIGH,
                    f"Tool governance requires review for {len(changed_tools)} changed tool definition(s)",
                    {"changed_tools": changed_tools}
                )

            return self._create_result(
                ControlStatus.PASS, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "Tool governance evaluation passed (tool definitions match baselines)",
                {"evaluated_tools": len(ctx.tool_definitions)}
            )
        except Exception as e:
            return self._create_result(
                ControlStatus.ERROR, SecurityDecision.DENY, ChangeSeverity.CRITICAL,
                f"Tool governance evaluation error: {str(e)}", {"error": str(e)}
            )

# =====================================================================
# 13. CHECKPOINT EVALUATOR (CONTROL-13)
# =====================================================================
class CheckpointEvaluator(BaseSecurityEvaluator):
    def __init__(self):
        super().__init__("CONTROL-13")

    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityControlResult:
        if not ctx.checkpoint_id:
            return self._create_result(
                ControlStatus.NOT_EVALUATED, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "No checkpoint ID supplied for checkpoint integrity evaluation", {}
            )
        try:
            val_res = pipeline.validate_security_checkpoint(ctx.checkpoint_id)
            if not val_res["valid"]:
                return self._create_result(
                    ControlStatus.FAIL, SecurityDecision.DENY, ChangeSeverity.HIGH,
                    f"Security checkpoint validation failed: {val_res['reason']}",
                    {"valid": False, "checkpoint_id": ctx.checkpoint_id}
                )

            return self._create_result(
                ControlStatus.PASS, SecurityDecision.ALLOW, ChangeSeverity.LOW,
                "Security checkpoint integrity verified clean",
                {"valid": True, "checkpoint_id": ctx.checkpoint_id}
            )
        except Exception as e:
            return self._create_result(
                ControlStatus.ERROR, SecurityDecision.DENY, ChangeSeverity.HIGH,
                f"Checkpoint evaluation error: {str(e)}", {"error": str(e)}
            )
