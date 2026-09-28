"""
Security Pipeline Module (Pre & Post execution inspection).
"""

from typing import Dict, Any, Tuple, Optional, List
from agentshield.core.config import ShieldConfig
from agentshield.core.exceptions import SecurityViolationError, PolicyViolationError
from agentshield.security.injection import PromptInjectionScanner
from agentshield.security.jailbreak import JailbreakDetector
from agentshield.security.sanitizer import InputOutputSanitizer
from agentshield.security.secrets import SecretDetector
from agentshield.policies.engine import PolicyEngine
from agentshield.provenance.logger import AuditLogger
from agentshield.provenance.telemetry import ExecutionTelemetry

from agentshield.context.boundary import InstructionBoundary
from agentshield.context.integrity import ContextIntegrityEngine
from agentshield.context.models import ContextItem, InstructionType, TrustLevel, SecurityDecision, ContextIntegrityResult, IntegrityStatus, UserIdentity
from agentshield.provenance.lineage import ProvenanceTracker
from agentshield.memory.models import MemoryRecord, MemoryAccessResult, MemoryWriteRequest, MemoryWriteResult
from agentshield.memory.security_engine import MemorySecurityEngine
from agentshield.memory.write_gate import MemoryWriteGate
from agentshield.memory.store import SafeMemoryStore
from agentshield.security.output_action_models import AgentOutput, OutputValidationResult, AgentAction, ActionValidationResult
from agentshield.security.output_action_validator import OutputActionValidator
from agentshield.security.egress_models import EgressRequest, EgressValidationResult
from agentshield.security.egress_validator import EgressValidator
from agentshield.security.audience_models import AudienceClaim, AudiencePolicy, SecurityTokenContext, AudienceValidationResult
from agentshield.security.audience_validator import AudienceValidator
from agentshield.security.tool_models import ToolDefinition, ToolBaseline, ToolChangeResult
from agentshield.security.tool_governance import ToolGovernanceRegistry
from agentshield.checkpoint.models import SecurityCheckpoint, RollbackRequest, RollbackResult
from agentshield.checkpoint.manager import CheckpointManager
from agentshield.evaluation.models import SecurityEvaluationContext, SecurityEvaluation
from agentshield.evaluation.engine import SecurityEvaluationEngine

class SecurityPipeline:
    """Executes pre-execution and post-execution security controls."""

    def __init__(self, config: ShieldConfig = None):
        self.config = config or ShieldConfig()
        self.injection_scanner = PromptInjectionScanner(threshold=self.config.injection_threshold)
        self.jailbreak_detector = JailbreakDetector(threshold=self.config.jailbreak_threshold)
        self.sanitizer = InputOutputSanitizer(mask_pii=self.config.enable_pii_sanitization)
        self.secret_detector = SecretDetector()
        self.policy_engine = PolicyEngine(policy_file_path=self.config.policy_file_path)
        self.audit_logger = AuditLogger(log_file_path=self.config.audit_log_path)
        self.telemetry = ExecutionTelemetry()
        self.instruction_boundary = InstructionBoundary()
        self.integrity_engine = ContextIntegrityEngine()
        self.memory_security_engine = MemorySecurityEngine(
            boundary=self.instruction_boundary,
            integrity_engine=self.integrity_engine,
            injection_scanner=self.injection_scanner,
            policy_engine=self.policy_engine
        )
        self.memory_write_gate = MemoryWriteGate(
            integrity_engine=self.integrity_engine,
            injection_scanner=self.injection_scanner,
            secret_detector=self.secret_detector,
            audit_logger=self.audit_logger
        )
        self.output_action_validator = OutputActionValidator(
            secret_detector=self.secret_detector,
            audit_logger=self.audit_logger,
            policy_engine=self.policy_engine
        )
        self.egress_validator = EgressValidator(
            secret_detector=self.secret_detector,
            audit_logger=self.audit_logger,
            policy_engine=self.policy_engine
        )
        self.audience_validator = AudienceValidator(
            audit_logger=self.audit_logger,
            policy_engine=self.policy_engine
        )
        self.tool_governance_registry = ToolGovernanceRegistry(
            audit_logger=self.audit_logger
        )
        self.checkpoint_manager = CheckpointManager(
            audit_logger=self.audit_logger
        )
        self.evaluation_engine = SecurityEvaluationEngine(
            audit_logger=self.audit_logger
        )




    def process_memory_retrieval(
        self,
        identity: Optional[UserIdentity],
        memory_records: List[MemoryRecord],
        tracker: Optional[ProvenanceTracker] = None
    ) -> List[ContextItem]:
        """
        Processes memory records through MemorySecurityEngine, enforcing user/tenant isolation,
        integrity, prompt injection detection, and converting to safe ContextItems.
        """
        valid_items: List[ContextItem] = []
        for record in memory_records:
            eval_res = self.memory_security_engine.evaluate_memory_access(identity, record, tracker=tracker)
            if not eval_res.authorized:
                self.audit_logger.log_event(
                    "MEMORY_ACCESS_DENIED",
                    {
                        "memory_id": record.memory_id,
                        "reason": eval_res.reason,
                        "violations": eval_res.violations
                    },
                    tenant_id=identity.tenant_id if identity else "unknown"
                )
                if self.config.strict_policy_mode and ("CROSS-USER" in eval_res.reason or "CROSS-TENANT" in eval_res.reason):
                    raise SecurityViolationError(f"Unauthorized memory access: {eval_res.reason}")
            elif eval_res.context_item:
                valid_items.append(eval_res.context_item)
        return valid_items

    def process_memory_write(
        self,
        request: MemoryWriteRequest,
        identity: Optional[UserIdentity] = None,
        tracker: Optional[ProvenanceTracker] = None,
        store: Optional[SafeMemoryStore] = None
    ) -> MemoryWriteResult:
        """
        Processes a memory write request through MemoryWriteGate before persistence into SafeMemoryStore.
        Raises SecurityViolationError in strict policy mode if unauthorized.
        """
        res = self.memory_write_gate.execute_memory_write(request, identity=identity, tracker=tracker, store=store)
        if not res.allowed and self.config.strict_policy_mode:
            if "CROSS-USER" in res.reason or "CROSS-TENANT" in res.reason:
                raise SecurityViolationError(f"Memory write denied: {res.reason}")
        return res

    def validate_agent_output(
        self,
        output: AgentOutput,
        identity: Optional[UserIdentity] = None,
        tracker: Optional[ProvenanceTracker] = None
    ) -> OutputValidationResult:
        """
        Validates generated agent output before external release.
        Raises SecurityViolationError in strict policy mode if output contains unauthorized cross-boundary content or secrets.
        """
        res = self.output_action_validator.validate_output(output, identity=identity, tracker=tracker)
        if not res.valid and self.config.strict_policy_mode:
            if "CROSS-USER" in res.reason or "CROSS-TENANT" in res.reason or res.sensitive_data_detected:
                raise SecurityViolationError(f"Agent output validation failed: {res.reason}")
        return res

    def validate_agent_action(
        self,
        action: AgentAction,
        identity: Optional[UserIdentity] = None,
        tracker: Optional[ProvenanceTracker] = None
    ) -> ActionValidationResult:
        """
        Validates proposed agent action before any execution approval.
        Raises SecurityViolationError in strict policy mode if action is unauthorized.
        """
        res = self.output_action_validator.validate_action(action, identity=identity, tracker=tracker)
        if not res.valid and self.config.strict_policy_mode:
            if "CROSS-USER" in res.reason or "CROSS-TENANT" in res.reason:
                raise SecurityViolationError(f"Agent action validation failed: {res.reason}")
        return res

    def validate_egress(
        self,
        request: EgressRequest,
        identity: Optional[UserIdentity] = None,
        tracker: Optional[ProvenanceTracker] = None
    ) -> EgressValidationResult:
        """
        Validates an egress request before information leaves the security boundary.
        Raises SecurityViolationError in strict policy mode if egress is denied.
        """
        res = self.egress_validator.validate_egress(request, identity=identity, tracker=tracker)
        if not res.allowed and self.config.strict_policy_mode and res.decision == SecurityDecision.DENY:
            raise SecurityViolationError(f"Egress validation denied: {res.reason}")
        return res

    def validate_audience(
        self,
        claim: AudienceClaim,
        identity: Optional[UserIdentity] = None,
        token_context: Optional[SecurityTokenContext] = None,
        policy: Optional[AudiencePolicy] = None,
        tracker: Optional[ProvenanceTracker] = None,
        raw_content: Optional[str] = None
    ) -> AudienceValidationResult:
        """
        Validates an audience claim before data disclosure or egress.
        Raises SecurityViolationError in strict policy mode if audience validation fails.
        """
        res = self.audience_validator.validate_audience(
            claim=claim,
            identity=identity,
            token_context=token_context,
            policy=policy,
            tracker=tracker,
            raw_content=raw_content
        )
        if not res.valid and self.config.strict_policy_mode and res.decision == SecurityDecision.DENY:
            raise SecurityViolationError(f"Audience validation denied: {res.reason}")
        return res

    def validate_tool_change(
        self,
        tool: ToolDefinition,
        expected_tool_id: Optional[str] = None,
        tracker: Optional[ProvenanceTracker] = None
    ) -> ToolChangeResult:
        """
        Validates a ToolDefinition against recorded baseline in ToolGovernanceRegistry.
        Detects drift in schemas, capabilities, security metadata, and identity.
        Raises SecurityViolationError in strict policy mode if decision is DENY.
        """
        res = self.tool_governance_registry.compare_tool_definition(tool, expected_tool_id=expected_tool_id, tracker=tracker)
        if self.config.strict_policy_mode and res.decision == SecurityDecision.DENY:
            raise SecurityViolationError(f"Tool change validation denied: {res.reason}")
        return res


    def approve_tool_change(
        self,
        tool_id: str,
        new_tool: ToolDefinition
    ) -> ToolBaseline:
        """
        Controlled baseline update upon explicit administrative approval.
        Updates baseline recorded in ToolGovernanceRegistry.
        """
        return self.tool_governance_registry.approve_tool_change(tool_id, new_tool)

    def create_security_checkpoint(
        self,
        created_by: str = "system",
        tenant_id: str = "default",
        description: str = "",
        provenance_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SecurityCheckpoint:
        """
        Creates an immutable SecurityCheckpoint of current tool baselines and security configuration.
        """
        baselines = self.tool_governance_registry.export_baselines()
        p_snap = self.policy_engine.export_policy() if hasattr(self.policy_engine, "export_policy") else {}
        c_snap = self.config.model_dump() if hasattr(self.config, "model_dump") else {}

        return self.checkpoint_manager.create_checkpoint(
            created_by=created_by,
            tenant_id=tenant_id,
            description=description,
            tool_baselines=baselines,
            policy_snapshot=p_snap,
            configuration_snapshot=c_snap,
            provenance_id=provenance_id,
            metadata=metadata
        )

    def validate_security_checkpoint(self, checkpoint_id_or_obj: Any) -> Dict[str, Any]:
        """
        Validates checkpoint integrity and structure in CheckpointManager.
        """
        return self.checkpoint_manager.validate_checkpoint(checkpoint_id_or_obj)

    def rollback_security_checkpoint(
        self,
        request: RollbackRequest,
        identity: Optional[UserIdentity] = None
    ) -> RollbackResult:
        """
        Executes explicit, governed rollback to a previous SecurityCheckpoint.
        Raises SecurityViolationError in strict policy mode if decision is DENY.
        """
        res = self.checkpoint_manager.execute_rollback(
            request=request,
            identity=identity,
            registry=self.tool_governance_registry,
            policy_engine=self.policy_engine,
            config=self.config
        )
        if self.config.strict_policy_mode and res.decision == SecurityDecision.DENY:
            raise SecurityViolationError(f"Security rollback denied: {res.reason}")
        return res

    def evaluate_security_posture(
        self,
        ctx: SecurityEvaluationContext
    ) -> SecurityEvaluation:
        """
        Executes a unified, evidence-based security evaluation over the provided context.
        Coordinates controls across SecurityPipeline, aggregates decisions, creates findings, and returns SecurityEvaluation.
        """
        return self.evaluation_engine.evaluate(ctx, self)



    def validate_context_integrity(
        self,
        context_items: list[ContextItem],
        tracker: Optional[ProvenanceTracker] = None,
        tenant_id: str = "default"
    ) -> ContextIntegrityResult:
        """
        Validates context items through ContextIntegrityEngine before agent execution,
        logging audit events for any detected violations.
        """
        result = self.integrity_engine.validate_context(context_items, tracker=tracker)
        
        if not result.valid:
            self.audit_logger.log_event(
                "CONTEXT_INTEGRITY_FAILURE",
                {
                    "status": result.integrity_status.value,
                    "violations": result.violations,
                    "item_count": result.item_count,
                    "validation_time_ms": result.validation_time_ms
                },
                tenant_id=tenant_id
            )
            if self.config.strict_policy_mode:
                raise SecurityViolationError(
                    f"Context integrity validation failed ({len(result.violations)} violations): {result.violations[0]}",
                    details={"violations": result.violations}
                )
                
        return result

    def process_instruction_context(
        self,
        context_items: list[ContextItem],
        tenant_id: str = "default"
    ) -> Tuple[str, list[ContextItem]]:
        """
        Processes a list of ContextItems through instruction boundary isolation,
        enforcing priority order, trust preservation, and returning a safe prompt string.
        """
        processed_items = self.instruction_boundary.process_context_items(context_items)
        safe_prompt = self.instruction_boundary.format_safe_prompt(processed_items)
        
        self.audit_logger.log_event(
            "CONTEXT_PROCESSED",
            {"item_count": len(processed_items), "tenant_id": tenant_id},
            tenant_id=tenant_id
        )
        return safe_prompt, processed_items

    def inspect_input(self, text: str, tenant_id: str = "default") -> Tuple[str, Dict[str, Any]]:
        """
        Runs pre-execution security checks on user input.
        Returns (sanitized_input, inspection_metadata).
        """
        self.telemetry.record_event("total_requests")

        # 1. Prompt Injection Scan
        if self.config.enable_injection_detection:
            inj_res = self.injection_scanner.scan(text)
            if inj_res["is_injection"]:
                self.telemetry.record_event("blocked_injections")
                self.audit_logger.log_event("INJECTION_BLOCKED", inj_res, tenant_id=tenant_id)
                raise SecurityViolationError(
                    f"Prompt injection detected (score: {inj_res['max_score']})",
                    details=inj_res
                )

        # 2. Jailbreak Detection
        if self.config.enable_jailbreak_detection:
            jb_res = self.jailbreak_detector.analyze(text)
            if jb_res["is_jailbreak"]:
                self.telemetry.record_event("blocked_jailbreaks")
                self.audit_logger.log_event("JAILBREAK_BLOCKED", jb_res, tenant_id=tenant_id)
                raise SecurityViolationError(
                    f"Jailbreak attempt detected: {jb_res['detected_vector']}",
                    details=jb_res
                )

        # 3. Secret Detection in input
        if self.config.enable_secret_detection:
            sec_res = self.secret_detector.detect_secrets(text)
            if sec_res["has_secrets"]:
                self.telemetry.record_event("detected_secrets")
                text = self.secret_detector.redact_secrets(text)

        # 4. PII Sanitization
        sanitized_text, pii_stats = self.sanitizer.sanitize_input(text)
        if pii_stats:
            self.telemetry.record_event("sanitized_pii", sum(pii_stats.values()))

        meta = {
            "pii_redact_stats": pii_stats,
            "status": "APPROVED"
        }

        self.audit_logger.log_event("INPUT_INSPECTED", meta, tenant_id=tenant_id)
        return sanitized_text, meta

    def inspect_output(self, output: str, tenant_id: str = "default") -> str:
        """Runs post-execution security checks and output sanitization."""
        # Check secrets leakage in output
        if self.config.enable_secret_detection:
            output = self.secret_detector.redact_secrets(output)

        # PII output filtering
        if self.config.enable_pii_sanitization:
            output, _ = self.sanitizer.sanitize_output(output)

        self.audit_logger.log_event("OUTPUT_INSPECTED", {"length": len(output)}, tenant_id=tenant_id)
        return output
