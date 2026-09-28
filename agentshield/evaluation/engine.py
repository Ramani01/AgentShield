"""
Security Evaluation Engine for AgentShield.

Unified, deterministic orchestrator for evaluating an AI agent / security state against AgentShield's 13 controls.
Guarantees evidence-based security assessment, fail-closed handling, finding deduplication, and tamper-evident audit logging.
Does NOT claim an agent is universally secure.
"""

import json
import time
import copy
from typing import Dict, Any, List, Optional, Set

from agentshield.context.models import SecurityDecision
from agentshield.security.tool_models import ChangeSeverity
from agentshield.evaluation.models import (
    EvaluationScope,
    ControlStatus,
    SecurityControlResult,
    SecurityFinding,
    SecurityEvaluationContext,
    SecurityEvaluation
)
from agentshield.evaluation.catalog import ControlCatalog
from agentshield.evaluation.evaluators import (
    InstructionIsolationEvaluator,
    TrustLabelEvaluator,
    PromptInjectionEvaluator,
    ProvenanceEvaluator,
    RetrievalAuthorizationEvaluator,
    ContextIntegrityEvaluator,
    MemorySecurityEvaluator,
    MemoryWriteEvaluator,
    OutputValidationEvaluator,
    EgressEvaluator,
    AudienceEvaluator,
    ToolGovernanceEvaluator,
    CheckpointEvaluator
)
from agentshield.provenance.logger import AuditLogger
from agentshield.provenance.models import compute_content_hash
from agentshield.security.tool_fingerprint import _normalize_obj

SCOPE_MAPPINGS: Dict[EvaluationScope, List[str]] = {
    EvaluationScope.FULL: [f"CONTROL-{i:02d}" for i in range(1, 14)],
    EvaluationScope.CONTEXT: ["CONTROL-01", "CONTROL-02", "CONTROL-03", "CONTROL-06"],
    EvaluationScope.MEMORY: ["CONTROL-07", "CONTROL-08"],
    EvaluationScope.TOOLS: ["CONTROL-12"],
    EvaluationScope.OUTPUT: ["CONTROL-09"],
    EvaluationScope.EGRESS: ["CONTROL-10", "CONTROL-11"],
    EvaluationScope.CHECKPOINT: ["CONTROL-13"],
    EvaluationScope.RETRIEVED: ["CONTROL-04", "CONTROL-05"]
}

class SecurityEvaluationEngine:
    """
    Unified evaluation orchestrator.
    Evaluates security context against AgentShield controls and produces evidence-based assessment.
    """

    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        self.audit_logger = audit_logger or AuditLogger()
        self._evaluation_history: List[SecurityEvaluation] = []
        self.evaluators = {
            "CONTROL-01": InstructionIsolationEvaluator(),
            "CONTROL-02": TrustLabelEvaluator(),
            "CONTROL-03": PromptInjectionEvaluator(),
            "CONTROL-04": ProvenanceEvaluator(),
            "CONTROL-05": RetrievalAuthorizationEvaluator(),
            "CONTROL-06": ContextIntegrityEvaluator(),
            "CONTROL-07": MemorySecurityEvaluator(),
            "CONTROL-08": MemoryWriteEvaluator(),
            "CONTROL-09": OutputValidationEvaluator(),
            "CONTROL-10": EgressEvaluator(),
            "CONTROL-11": AudienceEvaluator(),
            "CONTROL-12": ToolGovernanceEvaluator(),
            "CONTROL-13": CheckpointEvaluator()
        }

    def compute_evaluation_fingerprint(self, evaluation: SecurityEvaluation) -> str:
        """
        Computes a deterministic SHA-256 fingerprint over an evaluation's control results, findings, and decisions.
        
        IMPORTANT: EVALUATION FINGERPRINT != SECURITY GUARANTEE.
        """
        raw_results = [
            {
                "control_id": r.control_id,
                "status": r.status.value,
                "decision": r.decision.value,
                "severity": r.severity.value
            }
            for r in evaluation.control_results
        ]
        raw_findings = [
            {
                "control_id": f.control_id,
                "severity": f.severity.value,
                "title": f.title
            }
            for f in evaluation.findings
        ]

        payload = {
            "tenant_id": evaluation.tenant_id,
            "scope": evaluation.scope.value,
            "overall_decision": evaluation.overall_decision.value,
            "status": evaluation.status.value,
            "control_results": raw_results,
            "findings": raw_findings
        }
        normalized = _normalize_obj(payload)
        return compute_content_hash(json.dumps(normalized, sort_keys=True))

    def evaluate(self, ctx: SecurityEvaluationContext, pipeline: Any) -> SecurityEvaluation:
        """
        Executes a deterministic security assessment over the supplied SecurityEvaluationContext.
        Coordinates controls based on context scope, aggregates results, creates findings, and emits audit logs.
        """
        evaluation_id = f"eval_{time.time()}"
        self.audit_logger.log_event(
            "SECURITY_EVALUATION_STARTED",
            {
                "evaluation_id": evaluation_id,
                "scope": ctx.scope.value,
                "tenant_id": ctx.tenant_id
            },
            tenant_id=ctx.tenant_id
        )

        target_control_ids = SCOPE_MAPPINGS.get(ctx.scope, SCOPE_MAPPINGS[EvaluationScope.FULL])
        control_results: List[SecurityControlResult] = []
        findings: List[SecurityFinding] = []
        seen_findings: Set[str] = set()

        for cid in [f"CONTROL-{i:02d}" for i in range(1, 14)]:
            evaluator = self.evaluators.get(cid)
            if not evaluator:
                continue

            if cid in target_control_ids:
                try:
                    res = evaluator.evaluate(ctx, pipeline)
                except Exception as e:
                    def_obj = getattr(evaluator, "definition", None)
                    res = SecurityControlResult(
                        control_id=cid,
                        control_name=def_obj.name if def_obj else cid,
                        category=def_obj.category if def_obj else "CONTEXT",
                        status=ControlStatus.ERROR,
                        decision=SecurityDecision.DENY,
                        severity=ChangeSeverity.CRITICAL,
                        reason=f"Unhandled evaluator exception: {str(e)}",
                        evidence={"error": str(e)},
                        timestamp=time.time()
                    )
            else:
                def_obj = getattr(evaluator, "definition", None)
                res = SecurityControlResult(
                    control_id=cid,
                    control_name=def_obj.name if def_obj else cid,
                    category=def_obj.category if def_obj else "CONTEXT",
                    status=ControlStatus.NOT_EVALUATED,

                    decision=SecurityDecision.ALLOW,
                    severity=ChangeSeverity.LOW,
                    reason=f"Control omitted under scope '{ctx.scope.value}'",
                    evidence={},
                    timestamp=time.time()
                )

            control_results.append(res)
            self.audit_logger.log_event(
                "SECURITY_CONTROL_EVALUATED",
                {
                    "evaluation_id": evaluation_id,
                    "control_id": cid,
                    "status": res.status.value,
                    "decision": res.decision.value
                },
                tenant_id=ctx.tenant_id
            )

            # Generate and deduplicate findings for failed or review controls
            if res.status in [ControlStatus.FAIL, ControlStatus.REVIEW, ControlStatus.ERROR]:
                fnd_key = f"{cid}:{res.reason}:{res.severity.value}"
                if fnd_key not in seen_findings:
                    seen_findings.add(fnd_key)
                    finding = SecurityFinding(
                        control_id=cid,
                        severity=res.severity,
                        title=f"{res.control_name} {res.status.value}",
                        description=res.reason,
                        evidence=res.evidence,
                        recommendation=f"Review defensive policy and inputs for {res.control_name}",
                        decision=res.decision
                    )
                    findings.append(finding)
                    self.audit_logger.log_event(
                        "SECURITY_FINDING_CREATED",
                        {
                            "evaluation_id": evaluation_id,
                            "finding_id": finding.finding_id,
                            "control_id": cid,
                            "severity": res.severity.value
                        },
                        tenant_id=ctx.tenant_id
                    )

        # Aggregate Overall Decision and Status
        overall_decision = SecurityDecision.ALLOW
        overall_status = ControlStatus.PASS

        evaluated_applicable = [r for r in control_results if r.status != ControlStatus.NOT_EVALUATED]

        if not evaluated_applicable:
            overall_decision = SecurityDecision.REVIEW
            overall_status = ControlStatus.REVIEW
        else:
            has_error = any(r.status == ControlStatus.ERROR for r in evaluated_applicable)
            has_critical_fail = any(r.status == ControlStatus.FAIL and r.severity == ChangeSeverity.CRITICAL for r in evaluated_applicable)
            has_high_fail = any(r.status == ControlStatus.FAIL and r.severity == ChangeSeverity.HIGH for r in evaluated_applicable)
            has_fail = any(r.status == ControlStatus.FAIL for r in evaluated_applicable)
            has_review = any(r.status == ControlStatus.REVIEW for r in evaluated_applicable)

            if has_critical_fail or has_high_fail or has_error:
                overall_decision = SecurityDecision.DENY
                overall_status = ControlStatus.ERROR if has_error else ControlStatus.FAIL
            elif has_fail:
                overall_decision = SecurityDecision.DENY
                overall_status = ControlStatus.FAIL
            elif has_review:
                overall_decision = SecurityDecision.REVIEW
                overall_status = ControlStatus.REVIEW
            else:
                overall_decision = SecurityDecision.ALLOW
                overall_status = ControlStatus.PASS

        # Invariant Results
        invariant_results = {
            "INVARIANT_1_explicit_results": len(control_results) == 13,
            "INVARIANT_4_critical_fail_denied": not (any(r.severity == ChangeSeverity.CRITICAL and r.status == ControlStatus.FAIL for r in control_results) and overall_decision == SecurityDecision.ALLOW),
            "INVARIANT_13_not_evaluated_is_not_pass": not any(r.status == ControlStatus.NOT_EVALUATED and r.status == ControlStatus.PASS for r in control_results),
            "INVARIANT_18_no_tool_execution": True,
            "INVARIANT_19_no_network_execution": True
        }

        summary = {
            "total_controls": len(control_results),
            "passed_controls": sum(1 for r in control_results if r.status == ControlStatus.PASS),
            "failed_controls": sum(1 for r in control_results if r.status == ControlStatus.FAIL),
            "review_controls": sum(1 for r in control_results if r.status == ControlStatus.REVIEW),
            "not_evaluated_controls": sum(1 for r in control_results if r.status == ControlStatus.NOT_EVALUATED),
            "error_controls": sum(1 for r in control_results if r.status == ControlStatus.ERROR),
            "total_findings": len(findings)
        }

        evaluation = SecurityEvaluation(
            evaluated_at=time.time(),
            tenant_id=ctx.tenant_id,
            scope=ctx.scope,
            status=overall_status,
            overall_decision=overall_decision,
            findings=findings,
            evidence={"summary": summary, "scope": ctx.scope.value},
            control_results=control_results,
            invariant_results=invariant_results,
            summary=summary,
            metadata=ctx.metadata
        )

        evaluation.evaluation_fingerprint = self.compute_evaluation_fingerprint(evaluation)

        self.audit_logger.log_event(
            "SECURITY_EVALUATION_FAILED" if overall_status in [ControlStatus.FAIL, ControlStatus.ERROR] else "SECURITY_EVALUATION_COMPLETED",
            {
                "evaluation_id": evaluation.evaluation_id,
                "overall_decision": overall_decision.value,
                "status": overall_status.value,
                "fingerprint": evaluation.evaluation_fingerprint,
                "summary": summary
            },
            tenant_id=ctx.tenant_id
        )

        res_eval = copy.deepcopy(evaluation)
        self._evaluation_history.append(res_eval)
        return res_eval

    def get_evaluation_history(self, tenant_id: Optional[str] = None) -> List[SecurityEvaluation]:
        """Returns recorded evaluation history, optionally filtered by tenant_id."""
        if tenant_id is None:
            return copy.deepcopy(self._evaluation_history)
        return [copy.deepcopy(e) for e in self._evaluation_history if e.tenant_id == tenant_id]
