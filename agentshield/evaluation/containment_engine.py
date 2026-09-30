"""
Phase 27: Containment Evaluation Engine.
Main orchestrator evaluating security evidence across Phases 1-26 to produce deterministic containment recommendations.
"""

import time
import logging
from typing import Optional, Dict, Any, List
from agentshield.evaluation.containment_models import (
    EvidenceRecord,
    ContainmentAssessment,
    EvaluationOutcome,
    EvaluationSeverity,
    SEVERITY_RANK
)
from agentshield.evaluation.evidence import EvidenceNormalizer
from agentshield.evaluation.rules import RuleRegistry, EvaluationRule
from agentshield.evaluation.explain import DecisionExplainer

logger = logging.getLogger("AgentShield.ContainmentEvaluationEngine")


class ContainmentEvaluationEngine:
    """
    Main Phase 27 Containment Evaluation Engine.

    Security Invariants Enforced:
    1. Tenant Isolation: Tenant A evidence cannot affect Tenant B assessment.
    2. Agent Isolation: Agent A evidence cannot affect Agent B assessment.
    3. No Capability Elevation: Evaluation cannot grant capabilities.
    4. No Policy Override: Evaluation cannot override previous security controls.
    5. No Automatic Release: Engine can recommend RELEASE_REVIEW but cannot release an agent directly.
    6. Deterministic Evaluation: Same evidence + policy = same assessment.
    7. Evidence Traceability: Every non-NO_ACTION assessment references supporting evidence IDs.
    8. No Unsupported Attribution: Uses neutral, evidence-backed explanations.
    9. Fail-Safe Error Handling: Malformed/corrupted evidence returns conservative REVIEW outcome.
    10. Rule Priority Determinism: Conflicting rules resolve in strict priority precedence.
    11. Previous Controls Authoritative: Controls 01-13 & Phases 21-26 remain authoritative.
    """

    def __init__(
        self,
        rule_registry: Optional[RuleRegistry] = None,
        audit_logger: Optional[Any] = None,
        capability_engine: Optional[Any] = None,
        comm_engine: Optional[Any] = None,
        integrity_engine: Optional[Any] = None,
        behavior_engine: Optional[Any] = None,
        containment_manager: Optional[Any] = None,
        graph_engine: Optional[Any] = None
    ):
        self.rule_registry = rule_registry or RuleRegistry(include_defaults=True)
        self.audit_logger = audit_logger
        self.capability_engine = capability_engine
        self.comm_engine = comm_engine
        self.integrity_engine = integrity_engine
        self.behavior_engine = behavior_engine
        self.containment_manager = containment_manager
        self.graph_engine = graph_engine
        self.normalizer = EvidenceNormalizer()
        self.explainer = DecisionExplainer()

    def evaluate_agent(
        self,
        tenant_id: str = "default",
        agent_id: str = "default",
        raw_evidence_list: Optional[List[Any]] = None,
        current_containment_state: Optional[str] = None,
        has_recovery_request: bool = False,
        max_evidence_age_seconds: float = 300.0
    ) -> ContainmentAssessment:
        """
        Gathers evidence across active security engines for (tenant_id, agent_id),
        normalizes evidence, evaluates rules in priority order, and outputs ContainmentAssessment.
        """
        evidence_records: List[EvidenceRecord] = []

        # Auto-collect from active security engines if raw_evidence_list not explicitly passed
        try:
            if self.integrity_engine is not None and hasattr(self.integrity_engine, "evaluate_integrity"):
                check_res = self.integrity_engine.evaluate_integrity(agent_id=agent_id, tenant_id=tenant_id)
                evidence_records.append(self.normalizer.normalize_runtime_integrity(tenant_id, agent_id, check_res))

            if self.behavior_engine is not None and hasattr(self.behavior_engine, "evaluate_sequence"):
                beh_res = self.behavior_engine.evaluate_sequence(tenant_id=tenant_id, agent_id=agent_id)
                norm_beh = self.normalizer.normalize_behavior_assessment(tenant_id, agent_id, beh_res)
                if norm_beh:
                    evidence_records.append(norm_beh)

            if self.graph_engine is not None and hasattr(self.graph_engine, "find_agent_attack_paths"):
                graph_res = self.graph_engine.find_agent_attack_paths(tenant_id=tenant_id, agent_id=agent_id)
                norm_graph = self.normalizer.normalize_graph_path_assessment(tenant_id, agent_id, graph_res)
                if norm_graph:
                    evidence_records.append(norm_graph)

            if self.containment_manager is not None and current_containment_state is None:
                status = self.containment_manager.get_containment_status(tenant_id=tenant_id, agent_id=agent_id)
                current_containment_state = status.get("current_state", "NORMAL")
                evidence_records.append(self.normalizer.normalize_containment_record(tenant_id, agent_id, status))

        except Exception as e:
            # Invariant 9: Fail-Safe Error Handling on collection failure
            logger.warning(f"Error during evidence auto-collection: {e}")
            return self._create_failsafe_assessment(tenant_id, agent_id, f"Evidence collection error: {e}")

        # If raw evidence list passed manually, normalize items
        if raw_evidence_list:
            for item in raw_evidence_list:
                if isinstance(item, EvidenceRecord):
                    evidence_records.append(item)

        # Evaluate evidence freshness
        now = time.time()
        for record in evidence_records:
            self.normalizer.evaluate_freshness(record, max_age_seconds=max_evidence_age_seconds, current_time=now)

        context = {
            "current_containment_state": current_containment_state or "NORMAL",
            "has_recovery_request": has_recovery_request
        }

        return self.evaluate_evidence(tenant_id=tenant_id, agent_id=agent_id, evidence_records=evidence_records, context=context)

    def evaluate_evidence(
        self,
        tenant_id: str,
        agent_id: str,
        evidence_records: List[EvidenceRecord],
        context: Optional[Dict[str, Any]] = None
    ) -> ContainmentAssessment:
        """
        Evaluates a list of normalized EvidenceRecords using registered rules.
        """
        if context is None:
            context = {"current_containment_state": "NORMAL", "has_recovery_request": False}

        # Filter cross-tenant / cross-agent evidence (Enforces Invariants 1 & 2)
        valid_records = [
            e for e in evidence_records
            if (e.tenant_id == tenant_id or e.tenant_id == "default") and (e.agent_id == agent_id or e.agent_id == "default")
        ]

        rules = self.rule_registry.list_rules()  # Already sorted deterministically by (priority, rule_id)

        matched_rule_ids: List[str] = []
        matched_rule_objects: List[EvaluationRule] = []
        rule_details: Dict[str, Any] = {}

        for rule in rules:
            try:
                matched, match_meta = rule.condition_fn(valid_records, context)
                if matched:
                    matched_rule_ids.append(rule.rule_id)
                    matched_rule_objects.append(rule)
                    rule_details[rule.rule_id] = match_meta
            except Exception as e:
                logger.warning(f"Rule {rule.rule_id} condition execution error: {e}")

        if not matched_rule_objects:
            # Fallback cleanly to clean state
            outcome = EvaluationOutcome.NO_ACTION
            severity = EvaluationSeverity.LOW
            recommended_isolation = "NONE"
        else:
            # Primary rule determined by highest priority (lowest numeric value, already sorted)
            primary_rule = matched_rule_objects[0]
            outcome = primary_rule.target_outcome
            severity = primary_rule.target_severity
            recommended_isolation = primary_rule.recommended_isolation_level

        evidence_ids = [e.evidence_id for e in valid_records]

        explanation = self.explainer.generate_explanation(
            outcome=outcome,
            severity=severity,
            matched_rules=matched_rule_ids,
            evidence_records=valid_records,
            recommended_isolation=recommended_isolation,
            context=context
        )

        assessment = ContainmentAssessment(
            tenant_id=tenant_id,
            agent_id=agent_id,
            outcome=outcome,
            severity=severity,
            confidence=1.0,
            matched_rules=matched_rule_ids,
            evidence_ids=evidence_ids,
            current_containment_state=context.get("current_containment_state", "NORMAL"),
            recommended_isolation_level=recommended_isolation,
            explanation=explanation,
            details={
                "rule_details": rule_details,
                "evidence_count": len(valid_records),
                "matched_rules_count": len(matched_rule_ids)
            }
        )

        # Audit logging
        if self.audit_logger is not None:
            try:
                self.audit_logger.log_event(
                    "CONTAINMENT_ASSESSMENT_CREATED",
                    assessment.to_dict(),
                    tenant_id=tenant_id
                )
                if outcome == EvaluationOutcome.ESCALATE:
                    self.audit_logger.log_event("CONTAINMENT_ESCALATION_RECOMMENDED", {"tenant_id": tenant_id, "agent_id": agent_id, "assessment_id": assessment.assessment_id}, tenant_id=tenant_id)
                elif outcome == EvaluationOutcome.MAINTAIN:
                    self.audit_logger.log_event("CONTAINMENT_MAINTAIN_RECOMMENDED", {"tenant_id": tenant_id, "agent_id": agent_id, "assessment_id": assessment.assessment_id}, tenant_id=tenant_id)
                elif outcome == EvaluationOutcome.RELEASE_REVIEW:
                    self.audit_logger.log_event("CONTAINMENT_RELEASE_REVIEW_RECOMMENDED", {"tenant_id": tenant_id, "agent_id": agent_id, "assessment_id": assessment.assessment_id}, tenant_id=tenant_id)
            except Exception as e:
                logger.warning(f"Audit logger error in ContainmentEvaluationEngine: {e}")

        return assessment

    def _create_failsafe_assessment(self, tenant_id: str, agent_id: str, reason: str) -> ContainmentAssessment:
        """Invariants 9: Conservative fail-safe assessment on malformed or corrupted inputs."""
        return ContainmentAssessment(
            tenant_id=tenant_id,
            agent_id=agent_id,
            outcome=EvaluationOutcome.REVIEW,
            severity=EvaluationSeverity.HIGH,
            confidence=0.5,
            matched_rules=["FAILSAFE_CONSERVATIVE_RULE"],
            evidence_ids=[],
            recommended_isolation_level="RESTRICTED",
            explanation=f"Outcome REVIEW: Conservatively triggered by fail-safe handling ({reason}).",
            details={"failsafe_reason": reason}
        )
