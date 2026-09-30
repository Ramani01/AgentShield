"""
Phase 27: Evidence Normalization and Freshness Evaluator.
Normalizes raw security outputs from Phases 1-26 into canonical EvidenceRecords.
"""

import time
import logging
from typing import Dict, Any, List, Optional
from agentshield.evaluation.containment_models import EvidenceRecord, EvaluationSeverity

logger = logging.getLogger("AgentShield.EvidenceNormalizer")


class EvidenceNormalizer:
    """
    Normalizes heterogeneous security signals from Phases 1-26 into canonical EvidenceRecords.

    Invariants Enforced:
    1. Tenant Isolation: Evidence records strictly preserve tenant_id scope.
    2. Agent Isolation: Evidence records strictly preserve agent_id scope.
    """

    @staticmethod
    def evaluate_freshness(
        record: EvidenceRecord,
        max_age_seconds: float = 300.0,
        current_time: Optional[float] = None
    ) -> str:
        """
        Evaluates deterministic evidence freshness against evaluation window.
        """
        now = current_time if current_time is not None else time.time()
        age = now - record.timestamp

        if age > (max_age_seconds * 2):
            record.freshness_status = "EXPIRED"
        elif age > max_age_seconds:
            record.freshness_status = "STALE"
        else:
            record.freshness_status = "CURRENT"

        return record.freshness_status

    @staticmethod
    def normalize_runtime_integrity(
        tenant_id: str, agent_id: str, integrity_data: Any
    ) -> EvidenceRecord:
        """Normalizes Phase 23 runtime integrity check outputs."""
        state = "UNKNOWN"
        if hasattr(integrity_data, "state"):
            raw_state = getattr(integrity_data, "state")
            state = raw_state.value if hasattr(raw_state, "value") else str(raw_state)
        elif hasattr(integrity_data, "integrity_state"):
            raw_state = getattr(integrity_data, "integrity_state")
            state = raw_state.value if hasattr(raw_state, "value") else str(raw_state)

        severity = EvaluationSeverity.LOW
        if state in ("INVALID", "DRIFTED"):
            severity = EvaluationSeverity.HIGH if state == "DRIFTED" else EvaluationSeverity.CRITICAL

        return EvidenceRecord(
            source_phase="Phase-23",
            source_control="PHASE_23_RUNTIME_INTEGRITY",
            evidence_type="RUNTIME_INTEGRITY",
            severity=severity,
            confidence=1.0,
            tenant_id=tenant_id,
            agent_id=agent_id,
            references={"integrity_state": state},
            metadata={"raw_state": state}
        )

    @staticmethod
    def normalize_behavior_assessment(
        tenant_id: str, agent_id: str, assessment: Any
    ) -> Optional[EvidenceRecord]:
        """Normalizes Phase 24 behavioral detection outputs."""
        if not assessment or not getattr(assessment, "matched", False):
            return None

        risk_level = getattr(assessment, "risk_level", "LOW")
        pattern_id = getattr(assessment, "pattern_id", "UNKNOWN")
        pattern_name = getattr(assessment, "pattern_name", "Unknown Pattern")

        severity = EvaluationSeverity.LOW
        if risk_level == "CRITICAL":
            severity = EvaluationSeverity.CRITICAL
        elif risk_level == "HIGH":
            severity = EvaluationSeverity.HIGH
        elif risk_level == "MEDIUM":
            severity = EvaluationSeverity.MEDIUM

        return EvidenceRecord(
            source_phase="Phase-24",
            source_control="PHASE_24_BEHAVIORAL_DETECTOR",
            evidence_type="BEHAVIOR_PATTERN",
            severity=severity,
            confidence=getattr(assessment, "confidence", 0.90),
            tenant_id=tenant_id,
            agent_id=agent_id,
            references={
                "pattern_id": pattern_id,
                "pattern_name": pattern_name,
                "risk_level": risk_level,
                "recommended_decision": getattr(assessment, "recommended_decision", "ALLOW")
            },
            metadata={"matched_events_count": len(getattr(assessment, "matched_events", []))}
        )

    @staticmethod
    def normalize_containment_record(
        tenant_id: str, agent_id: str, record_data: Any
    ) -> EvidenceRecord:
        """Normalizes Phase 25 containment state outputs."""
        curr_state = getattr(record_data, "current_state", getattr(record_data, "get", lambda k, d: d)("current_state", "NORMAL"))
        iso_level = getattr(record_data, "isolation_level", getattr(record_data, "get", lambda k, d: d)("isolation_level", "NONE"))

        severity = EvaluationSeverity.LOW
        if curr_state == "CONTAINED":
            severity = EvaluationSeverity.HIGH
        elif curr_state == "SUSPECTED":
            severity = EvaluationSeverity.MEDIUM

        return EvidenceRecord(
            source_phase="Phase-25",
            source_control="PHASE_25_CONTAINMENT_MANAGER",
            evidence_type="CONTAINMENT_STATE",
            severity=severity,
            confidence=1.0,
            tenant_id=tenant_id,
            agent_id=agent_id,
            references={"current_state": curr_state, "isolation_level": iso_level},
            metadata={"state": curr_state, "isolation_level": iso_level}
        )

    @staticmethod
    def normalize_graph_path_assessment(
        tenant_id: str, agent_id: str, path_assessment: Any
    ) -> Optional[EvidenceRecord]:
        """Normalizes Phase 26 security graph path assessment outputs."""
        if not path_assessment or not getattr(path_assessment, "paths", []):
            return None

        risk_level = getattr(path_assessment, "risk_level", "LOW")
        signals = getattr(path_assessment, "signals", [])

        severity = EvaluationSeverity.LOW
        if risk_level == "CRITICAL":
            severity = EvaluationSeverity.CRITICAL
        elif risk_level == "HIGH":
            severity = EvaluationSeverity.HIGH
        elif risk_level == "MEDIUM":
            severity = EvaluationSeverity.MEDIUM

        return EvidenceRecord(
            source_phase="Phase-26",
            source_control="PHASE_26_SECURITY_GRAPH",
            evidence_type="SECURITY_GRAPH_PATH",
            severity=severity,
            confidence=0.95,
            tenant_id=tenant_id,
            agent_id=agent_id,
            references={"risk_level": risk_level, "signals": signals, "paths_count": len(getattr(path_assessment, "paths", []))},
            metadata={"signals": signals}
        )
