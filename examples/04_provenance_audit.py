"""
Example 04: Cryptographic Audit Logging & Lineage Tracking.
"""

from agentshield.provenance import AuditLogger, ActionLineage

def main():
    print("=== AgentShield Cryptographic Audit & Lineage Example ===")

    # 1. Audit Logger with Hash Chaining
    logger = AuditLogger(log_file_path="audit_logs/example_audit.jsonl")
    
    e1 = logger.log_event("USER_LOGIN", {"user": "alice"}, tenant_id="tenant_101")
    e2 = logger.log_event("AGENT_INVOKED", {"prompt": "Analyze dataset"}, tenant_id="tenant_101")
    e3 = logger.log_event("TOOL_EXECUTION", {"tool": "search_web"}, tenant_id="tenant_101")

    print("\n[Log Entry 3 Hash]:", e3["hash"])
    print("[Previous Hash Link]:", e3["prev_hash"])

    # 2. Verify Log Chain Integrity
    integrity = logger.verify_log_integrity()
    print("\n[Audit Log Integrity Verification]:", integrity)

    # 3. Action Lineage Graph Tracking
    lineage = ActionLineage()
    p_id = lineage.record_step("USER_PROMPT", "Input", "Tell me a story")
    t_id = lineage.record_step("TOOL_CALL", "search_web", "query: fantasy", parent_id=p_id)
    a_id = lineage.record_step("AGENT_OUTPUT", "Response", "Once upon a time...", parent_id=t_id)

    print("\n[Execution Lineage Graph]:")
    print(lineage.get_lineage_trace())

if __name__ == "__main__":
    main()
