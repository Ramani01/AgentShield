"""
Unit tests for cryptographic audit logger and lineage tracking.
"""

import os
from agentshield.provenance.logger import AuditLogger
from agentshield.provenance.lineage import ActionLineage
from agentshield.provenance.telemetry import ExecutionTelemetry

def test_audit_logger_integrity(tmp_path):
    log_file = tmp_path / "test_audit.jsonl"
    logger = AuditLogger(log_file_path=str(log_file))

    logger.log_event("EVENT_1", {"data": "A"})
    logger.log_event("EVENT_2", {"data": "B"})

    integrity = logger.verify_log_integrity()
    assert integrity["valid"]
    assert integrity["entries_checked"] == 2

def test_action_lineage():
    lineage = ActionLineage(trace_id="test_trace_123")
    n1 = lineage.record_step("USER_PROMPT", "Input", "Hello")
    n2 = lineage.record_step("AGENT_OUTPUT", "Response", "World", parent_id=n1)

    trace = lineage.get_lineage_trace()
    assert trace["trace_id"] == "test_trace_123"
    assert len(trace["nodes"]) == 2
    assert trace["nodes"][1]["parent_id"] == n1

def test_execution_telemetry():
    telemetry = ExecutionTelemetry()
    telemetry.record_event("blocked_injections", 2)
    telemetry.record_event("total_requests", 5)

    summary = telemetry.get_summary()
    assert summary["blocked_injections"] == 2
    assert summary["total_requests"] == 5
