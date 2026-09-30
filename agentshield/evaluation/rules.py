"""
Phase 27: Evaluation Rules and Conflict Resolution Engine.
Configurable, deterministic rules governing containment evaluation outcomes.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Callable
from agentshield.evaluation.containment_models import (
    EvidenceRecord,
    EvaluationOutcome,
    EvaluationSeverity,
    SEVERITY_RANK
)


@dataclass
class EvaluationRule:
    """Configurable containment evaluation rule."""
    rule_id: str
    name: str
    priority: int  # Lower number = higher precedence (e.g. 10 > 20)
    description: str
    target_outcome: str
    target_severity: str
    recommended_isolation_level: str
    condition_fn: Callable[[List[EvidenceRecord], Dict[str, Any]], Tuple[bool, Dict[str, Any]]]


class RuleRegistry:
    """Registry managing active containment evaluation rules with deterministic priority ordering."""

    def __init__(self, include_defaults: bool = True):
        self._rules: Dict[str, EvaluationRule] = {}
        if include_defaults:
            self._load_default_rules()

    def register_rule(self, rule: EvaluationRule) -> None:
        """Registers a rule."""
        if not rule or not rule.rule_id:
            raise ValueError("Invalid rule or rule_id")
        self._rules[rule.rule_id] = rule

    def list_rules(self) -> List[EvaluationRule]:
        """Returns all rules sorted deterministically by priority then rule_id."""
        rules = list(self._rules.values())
        rules.sort(key=lambda r: (r.priority, r.rule_id))
        return rules

    def _load_default_rules(self) -> None:
        """Loads standard deterministic evaluation rules."""
        default_rules = [
            # Rule 1 — Critical Behavioral Evidence
            EvaluationRule(
                rule_id="RULE-001",
                name="Critical Behavioral Evidence",
                priority=10,
                description="Phase 24 CRITICAL behavioral pattern triggers ESCALATE recommendation.",
                target_outcome=EvaluationOutcome.ESCALATE,
                target_severity=EvaluationSeverity.CRITICAL,
                recommended_isolation_level="FULL",
                condition_fn=self._cond_critical_behavior
            ),
            # Rule 2 — Invalid Runtime + Suspicious Behavior
            EvaluationRule(
                rule_id="RULE-002",
                name="Invalid Runtime with Suspicious Behavior",
                priority=20,
                description="INVALID runtime combined with HIGH/CRITICAL behavior triggers ESCALATE recommendation.",
                target_outcome=EvaluationOutcome.ESCALATE,
                target_severity=EvaluationSeverity.CRITICAL,
                recommended_isolation_level="FULL",
                condition_fn=self._cond_invalid_runtime_plus_behavior
            ),
            # Rule 2B — High Behavioral Risk
            EvaluationRule(
                rule_id="RULE-002B",
                name="High Behavioral Risk",
                priority=25,
                description="Phase 24 HIGH behavioral pattern triggers REVIEW recommendation.",
                target_outcome=EvaluationOutcome.REVIEW,
                target_severity=EvaluationSeverity.HIGH,
                recommended_isolation_level="RESTRICTED",
                condition_fn=self._cond_high_behavior
            ),
            # Rule 3 — Invalid/Drifted Runtime Standalone
            EvaluationRule(
                rule_id="RULE-003",
                name="Invalid Runtime Standalone",
                priority=30,
                description="INVALID or DRIFTED runtime environment triggers ESCALATE recommendation.",
                target_outcome=EvaluationOutcome.ESCALATE,
                target_severity=EvaluationSeverity.HIGH,
                recommended_isolation_level="FULL",
                condition_fn=self._cond_invalid_runtime
            ),
            # Rule 4 — Already Contained with Ongoing Risk
            EvaluationRule(
                rule_id="RULE-004",
                name="Already Contained Agent Ongoing Risk",
                priority=40,
                description="CONTAINED agent with ongoing HIGH/CRITICAL risk triggers MAINTAIN recommendation.",
                target_outcome=EvaluationOutcome.MAINTAIN,
                target_severity=EvaluationSeverity.HIGH,
                recommended_isolation_level="FULL",
                condition_fn=self._cond_already_contained_risk
            ),
            # Rule 5 — Suspicious Graph Path
            EvaluationRule(
                rule_id="RULE-005",
                name="Suspicious Graph Path Evidence",
                priority=50,
                description="Phase 26 SUSPICIOUS path or HIGH risk signals trigger REVIEW recommendation.",
                target_outcome=EvaluationOutcome.REVIEW,
                target_severity=EvaluationSeverity.HIGH,
                recommended_isolation_level="RESTRICTED",
                condition_fn=self._cond_suspicious_graph_path
            ),
            # Rule 6 — Recovery Review Criteria Satisfied
            EvaluationRule(
                rule_id="RULE-006",
                name="Recovery Review Criteria Satisfied",
                priority=60,
                description="CONTAINED agent with VALID runtime, no active HIGH risk, and authorized recovery triggers RELEASE_REVIEW recommendation.",
                target_outcome=EvaluationOutcome.RELEASE_REVIEW,
                target_severity=EvaluationSeverity.LOW,
                recommended_isolation_level="NONE",
                condition_fn=self._cond_recovery_review
            ),
            # Rule 8 — Unresolved High/Critical Risk Signal Fallback
            EvaluationRule(
                rule_id="RULE-008",
                name="Unresolved High/Critical Risk Signal",
                priority=90,
                description="Any unhandled HIGH or CRITICAL risk signal triggers REVIEW recommendation.",
                target_outcome=EvaluationOutcome.REVIEW,
                target_severity=EvaluationSeverity.HIGH,
                recommended_isolation_level="RESTRICTED",
                condition_fn=self._cond_unresolved_high_risk
            ),
            # Rule 7 — Clean State No Action
            EvaluationRule(
                rule_id="RULE-007",
                name="Clean State Baseline",
                priority=100,
                description="All evidence clean and VALID runtime triggers NO_ACTION outcome.",
                target_outcome=EvaluationOutcome.NO_ACTION,
                target_severity=EvaluationSeverity.LOW,
                recommended_isolation_level="NONE",
                condition_fn=self._cond_clean_state
            )
        ]
        for r in default_rules:
            self.register_rule(r)

    # Condition implementations
    @staticmethod
    def _cond_critical_behavior(ev_records: List[EvidenceRecord], ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        for ev in ev_records:
            if ev.evidence_type == "BEHAVIOR_PATTERN" and ev.severity == EvaluationSeverity.CRITICAL:
                return True, {"matched_evidence_id": ev.evidence_id, "pattern_id": ev.references.get("pattern_id")}
        return False, {}

    @staticmethod
    def _cond_high_behavior(ev_records: List[EvidenceRecord], ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        for ev in ev_records:
            if ev.evidence_type == "BEHAVIOR_PATTERN" and ev.severity == EvaluationSeverity.HIGH:
                return True, {"matched_evidence_id": ev.evidence_id, "pattern_id": ev.references.get("pattern_id")}
        return False, {}

    @staticmethod
    def _cond_invalid_runtime_plus_behavior(ev_records: List[EvidenceRecord], ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        has_invalid_rt = False
        has_high_beh = False
        ev_ids = []
        for ev in ev_records:
            if ev.evidence_type == "RUNTIME_INTEGRITY" and ev.references.get("integrity_state") == "INVALID":
                has_invalid_rt = True
                ev_ids.append(ev.evidence_id)
            if ev.evidence_type == "BEHAVIOR_PATTERN" and ev.severity in (EvaluationSeverity.HIGH, EvaluationSeverity.CRITICAL):
                has_high_beh = True
                ev_ids.append(ev.evidence_id)
        if has_invalid_rt and has_high_beh:
            return True, {"matched_evidence_ids": ev_ids}
        return False, {}

    @staticmethod
    def _cond_invalid_runtime(ev_records: List[EvidenceRecord], ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        for ev in ev_records:
            if ev.evidence_type == "RUNTIME_INTEGRITY" and ev.references.get("integrity_state") in ("INVALID", "DRIFTED"):
                return True, {"matched_evidence_id": ev.evidence_id, "integrity_state": ev.references.get("integrity_state")}
        return False, {}

    @staticmethod
    def _cond_already_contained_risk(ev_records: List[EvidenceRecord], ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        current_state = ctx.get("current_containment_state", "NORMAL")
        if current_state != "CONTAINED":
            return False, {}
        for ev in ev_records:
            if ev.severity in (EvaluationSeverity.HIGH, EvaluationSeverity.CRITICAL):
                return True, {"current_state": current_state, "matched_evidence_id": ev.evidence_id}
        return False, {}

    @staticmethod
    def _cond_suspicious_graph_path(ev_records: List[EvidenceRecord], ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        for ev in ev_records:
            if ev.evidence_type == "SECURITY_GRAPH_PATH" and ev.severity in (EvaluationSeverity.HIGH, EvaluationSeverity.CRITICAL):
                return True, {"matched_evidence_id": ev.evidence_id, "signals": ev.references.get("signals")}
        return False, {}

    @staticmethod
    def _cond_recovery_review(ev_records: List[EvidenceRecord], ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        current_state = ctx.get("current_containment_state", "NORMAL")
        has_recovery_req = ctx.get("has_recovery_request", False)
        if current_state not in ("CONTAINED", "RECOVERY") or not has_recovery_req:
            return False, {}
        # Check no active HIGH/CRITICAL evidence exists
        for ev in ev_records:
            if ev.severity in (EvaluationSeverity.HIGH, EvaluationSeverity.CRITICAL) and ev.freshness_status == "CURRENT":
                return False, {}
        return True, {"current_state": current_state, "has_recovery_request": True}

    @staticmethod
    def _cond_unresolved_high_risk(ev_records: List[EvidenceRecord], ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        for ev in ev_records:
            if ev.severity in (EvaluationSeverity.HIGH, EvaluationSeverity.CRITICAL):
                return True, {"matched_evidence_id": ev.evidence_id}
        return False, {}

    @staticmethod
    def _cond_clean_state(ev_records: List[EvidenceRecord], ctx: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        for ev in ev_records:
            if ev.severity in (EvaluationSeverity.HIGH, EvaluationSeverity.CRITICAL):
                return False, {}
        return True, {}

