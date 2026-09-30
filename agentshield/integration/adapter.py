"""
Framework-Independent Security Integration Adapter for AgentShield.
"""

import time
from typing import Dict, Any, Optional, List
from agentshield.core.config import ShieldConfig
from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.exceptions import SecurityViolationError, AgentShieldError
from agentshield.integration.models import (
    ShieldDecision,
    ShieldIdentity,
    ShieldRequest,
    ShieldOutputRequest,
    ShieldActionRequest,
    ShieldResponse
)
from agentshield.context.models import (
    ContextItem,
    UserIdentity,
    TrustLevel,
    InstructionType,
    SourceCategory,
    INSTRUCTION_PRIORITIES
)
from agentshield.provenance.models import compute_content_hash

from agentshield.security.output_action_models import AgentOutput, AgentAction
from agentshield.security.egress_models import EgressRequest
from agentshield.memory.models import MemoryRecord, MemoryWriteRequest
from agentshield.security.tool_models import ToolDefinition
from agentshield.evaluation.models import SecurityEvaluationContext


class AgentShieldAdapter:
    """
    Unified integration adapter connecting application workflows to AgentShield's
    security pipeline and governance controls.
    """

    def __init__(
        self,
        pipeline: Optional[SecurityPipeline] = None,
        config: Optional[ShieldConfig] = None,
        capability_engine: Optional[Any] = None
    ):
        self.config = config or ShieldConfig()
        self.pipeline = pipeline or SecurityPipeline(config=self.config)
        self.capability_engine = capability_engine

    def process_request(self, request: ShieldRequest) -> ShieldResponse:
        """
        Executes pre-execution security controls over incoming application requests.
        Enforces identity propagation, prompt injection scanning, jailbreak detection,
        secret redaction, PII sanitization, context integrity, and instruction isolation.
        """
        # Fail-closed check if identity or tenant_id is missing when strict policy is set
        if not request.identity or not request.identity.tenant_id:
            if self.config.strict_policy_mode:
                return ShieldResponse(
                    decision=ShieldDecision.DENY,
                    allowed=False,
                    reason="Fail-closed: Request identity or tenant_id context is missing.",
                    violations=["MISSING_TENANT_IDENTITY"]
                )

        identity = request.identity.to_user_identity() if request.identity else UserIdentity(user_id="anonymous", tenant_id="default")

        if self.capability_engine:
            from agentshield.capabilities.models import AgentCapability, CapabilityCheckRequest
            cap_res = self.capability_engine.check_capability(
                CapabilityCheckRequest(
                    capability=AgentCapability.READ_DOCUMENTS,
                    agent_id="default_agent",
                    tenant_id=identity.tenant_id,
                    identity=identity
                )
            )
            if not cap_res.allowed:
                return ShieldResponse(
                    decision=ShieldDecision.DENY,
                    allowed=False,
                    reason=f"Capability denied: {cap_res.reason}",
                    violations=[cap_res.reason]
                )

        try:
            # 1. Inspect input prompt for injections, jailbreaks, secrets, PII
            clean_prompt, meta = self.pipeline.inspect_input(request.prompt, tenant_id=identity.tenant_id)

            # 2. Context Items Integrity & Isolation
            context_items: List[ContextItem] = []
            if request.context_items:
                for c_raw in request.context_items:
                    itype = InstructionType.USER
                    if "instruction_type" in c_raw:
                        try:
                            itype = InstructionType(c_raw["instruction_type"])
                        except ValueError:
                            itype = InstructionType.USER

                    scat = SourceCategory.USER
                    if "source_category" in c_raw:
                        try:
                            scat = SourceCategory(c_raw["source_category"])
                        except ValueError:
                            scat = SourceCategory.EXTERNAL_DOCUMENT

                    tlevel = TrustLevel.UNTRUSTED
                    if "trust_level" in c_raw:
                        try:
                            tlevel = TrustLevel(c_raw["trust_level"])
                        except ValueError:
                            tlevel = TrustLevel.UNTRUSTED

                    if "is_instruction_allowed" in c_raw:
                        is_allowed = bool(c_raw["is_instruction_allowed"])
                    else:
                        is_allowed = (tlevel == TrustLevel.TRUSTED and itype in (InstructionType.SYSTEM, InstructionType.DEVELOPER))

                    content_str = c_raw.get("content", "")

                    context_items.append(ContextItem(
                        content=content_str,
                        raw_content=c_raw.get("raw_content", content_str),
                        instruction_type=itype,
                        source_category=scat,
                        trust_level=tlevel,
                        origin=c_raw.get("origin", c_raw.get("source_id", "app_context")),
                        provenance_id=c_raw.get("provenance_id"),
                        content_hash=compute_content_hash(content_str),
                        is_instruction_allowed=is_allowed,
                        priority=c_raw.get("priority", INSTRUCTION_PRIORITIES.get(itype, 0)),
                        metadata=c_raw.get("metadata", {})
                    ))



                # Context integrity validation
                int_res = self.pipeline.validate_context_integrity(context_items, tenant_id=identity.tenant_id)
                if not int_res.valid:
                    return ShieldResponse(
                        decision=ShieldDecision.ISOLATE,
                        allowed=False,
                        sanitized_content=clean_prompt,
                        reason=f"Context integrity violation: {int_res.violations[0]}",
                        violations=int_res.violations,
                        metadata=meta
                    )

                # Instruction context processing
                formatted_ctx, _ = self.pipeline.process_instruction_context(context_items, tenant_id=identity.tenant_id)
                clean_prompt = formatted_ctx + "\n" + clean_prompt


            return ShieldResponse(
                decision=ShieldDecision.ALLOW,
                allowed=True,
                sanitized_content=clean_prompt,
                metadata=meta
            )

        except SecurityViolationError as e:
            return ShieldResponse(
                decision=ShieldDecision.DENY,
                allowed=False,
                reason=str(e),
                violations=[str(e)],
                metadata=getattr(e, "details", {})
            )
        except Exception as e:
            return ShieldResponse(
                decision=ShieldDecision.DENY,
                allowed=False,
                reason=f"Unexpected pipeline security exception: {str(e)}",
                violations=["INTERNAL_SECURITY_EXCEPTION"]
            )

    def process_output(self, request: ShieldOutputRequest) -> ShieldResponse:
        """
        Validates and sanitizes agent output before returning to application callers.
        Redacts leaked secrets, filters PII, and enforces output safety contracts.
        """
        identity = request.identity.to_user_identity() if request.identity else UserIdentity(user_id="anonymous", tenant_id="default")

        # 1. Output object validation
        agent_out = AgentOutput(
            content=request.output_text,
            recipient=request.recipient,
            tenant_id=identity.tenant_id,
            user_id=identity.user_id
        )

        try:
            val_res = self.pipeline.validate_agent_output(agent_out, identity=identity)
            if not val_res.valid:
                dec = ShieldDecision.DENY
                if val_res.decision.value == "REVIEW":
                    dec = ShieldDecision.REVIEW
                return ShieldResponse(
                    decision=dec,
                    allowed=False,
                    reason=val_res.reason,
                    violations=val_res.violations
                )

            # 2. Secret Redaction & PII filtering
            clean_output = self.pipeline.inspect_output(request.output_text, tenant_id=identity.tenant_id)

            return ShieldResponse(
                decision=ShieldDecision.ALLOW,
                allowed=True,
                sanitized_content=clean_output
            )

        except SecurityViolationError as e:
            return ShieldResponse(
                decision=ShieldDecision.DENY,
                allowed=False,
                reason=str(e),
                violations=[str(e)]
            )

    def process_action(self, request: ShieldActionRequest) -> ShieldResponse:
        """
        Validates proposed agent action against safety policies and governance gates.
        """
        identity = request.identity.to_user_identity() if request.identity else UserIdentity(user_id="anonymous", tenant_id="default")

        if self.capability_engine:
            from agentshield.capabilities.models import AgentCapability, CapabilityCheckRequest
            cap_res = self.capability_engine.check_capability(
                CapabilityCheckRequest(
                    capability=AgentCapability.USE_TOOLS,
                    agent_id="default_agent",
                    tenant_id=identity.tenant_id,
                    identity=identity,
                    target=request.tool_id
                )
            )
            if not cap_res.allowed:
                return ShieldResponse(
                    decision=ShieldDecision.DENY,
                    allowed=False,
                    reason=f"Capability denied: {cap_res.reason}",
                    violations=[cap_res.reason]
                )

        action = AgentAction(
            action_type=request.action_type,
            target=request.tool_id,
            parameters=request.parameters,
            tenant_id=identity.tenant_id,
            user_id=identity.user_id
        )

        try:
            val_res = self.pipeline.validate_agent_action(action, identity=identity)
            if not val_res.valid:
                dec = ShieldDecision.DENY
                if val_res.decision.value == "REVIEW":
                    dec = ShieldDecision.REVIEW
                return ShieldResponse(
                    decision=dec,
                    allowed=False,
                    reason=val_res.reason,
                    violations=val_res.violations
                )

            return ShieldResponse(
                decision=ShieldDecision.ALLOW,
                allowed=True
            )

        except SecurityViolationError as e:
            return ShieldResponse(
                decision=ShieldDecision.DENY,
                allowed=False,
                reason=str(e),
                violations=[str(e)]
            )


    def process_memory_retrieval(
        self,
        identity: ShieldIdentity,
        memory_records: List[MemoryRecord]
    ) -> List[Dict[str, Any]]:
        """
        Evaluates memory records for safe retrieval in the current identity context.
        """
        user_ident = identity.to_user_identity()
        safe_items = self.pipeline.process_memory_retrieval(user_ident, memory_records)
        return [item.model_dump() for item in safe_items]

    def process_memory_write(
        self,
        write_request: MemoryWriteRequest,
        identity: ShieldIdentity
    ) -> ShieldResponse:
        """
        Evaluates memory write request through memory write gates.
        """
        user_ident = identity.to_user_identity()
        try:
            res = self.pipeline.process_memory_write(write_request, identity=user_ident)
            if not res.allowed:
                return ShieldResponse(
                    decision=ShieldDecision.DENY,
                    allowed=False,
                    reason=res.reason,
                    violations=res.violations
                )
            return ShieldResponse(
                decision=ShieldDecision.ALLOW,
                allowed=True
            )
        except SecurityViolationError as e:
            return ShieldResponse(
                decision=ShieldDecision.DENY,
                allowed=False,
                reason=str(e),
                violations=[str(e)]
            )

    def validate_egress(
        self,
        egress_request: EgressRequest,
        identity: ShieldIdentity
    ) -> ShieldResponse:
        """
        Evaluates egress request against egress policy controls.
        """
        user_ident = identity.to_user_identity()
        try:
            res = self.pipeline.validate_egress(egress_request, identity=user_ident)
            if not res.allowed:
                return ShieldResponse(
                    decision=ShieldDecision.DENY,
                    allowed=False,
                    reason=res.reason,
                    violations=res.violations
                )
            return ShieldResponse(
                decision=ShieldDecision.ALLOW,
                allowed=True
            )
        except SecurityViolationError as e:
            return ShieldResponse(
                decision=ShieldDecision.DENY,
                allowed=False,
                reason=str(e),
                violations=[str(e)]
            )

    def validate_tool_governance(self, tool: ToolDefinition) -> ShieldResponse:
        """
        Evaluates tool definition for change detection and governance drift.
        """
        try:
            res = self.pipeline.validate_tool_change(tool)
            dec = ShieldDecision.ALLOW
            if res.decision.value == "DENY":
                dec = ShieldDecision.DENY
            elif res.decision.value == "REVIEW":
                dec = ShieldDecision.REVIEW

            return ShieldResponse(
                decision=dec,
                allowed=(dec == ShieldDecision.ALLOW),
                reason=res.reason,
                metadata={"changed": res.changed, "changed_fields": res.changed_fields}
            )
        except SecurityViolationError as e:
            return ShieldResponse(
                decision=ShieldDecision.DENY,
                allowed=False,
                reason=str(e),
                violations=[str(e)]
            )

    def evaluate_security_posture(self, eval_ctx: SecurityEvaluationContext) -> Dict[str, Any]:
        """
        Executes complete security evaluation across the evaluation engine.
        """
        eval_res = self.pipeline.evaluate_security_posture(eval_ctx)
        return eval_res.model_dump()
