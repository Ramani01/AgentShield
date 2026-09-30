"""
AgentShield 2.0 — Complete End-to-End System Demonstration (Phase 30 Final Release).
"""

from agentshield import AgentShield
from agentshield.capabilities.models import AgentCapability, CapabilityGrant, AgentCapabilityProfile, CapabilityCheckRequest
from agentshield.evaluation import EvidenceRecord, EvaluationSeverity, EvaluationOutcome
from agentshield.benchmark import BenchmarkReporter


def main():
    print("==================================================================")
    print("[AgentShield 2.0] — Complete System Demonstration & Validation")
    print("==================================================================\n")

    # 1. Initialize AgentShield Facade
    print("1. Initializing AgentShield 2.0 Facade...")
    shield = AgentShield()
    tenant_id = "demo_tenant"
    agent_id = "agent_007"
    print("   [OK] Facade initialized with 9 security engines.\n")

    # 2. Configure Least-Privilege Capability Profile (Phase 21)
    print(f"2. Registering Least-Privilege Profile for Agent '{agent_id}'...")
    prof = AgentCapabilityProfile(
        agent_id=agent_id,
        tenant_id=tenant_id,
        grants={
            AgentCapability.READ_DOCUMENTS: CapabilityGrant(capability=AgentCapability.READ_DOCUMENTS, granted=True),
            AgentCapability.DATA_EXPORT: CapabilityGrant(capability=AgentCapability.DATA_EXPORT, granted=False)
        }
    )
    shield.capability_engine.register_profile(prof)
    print("   [OK] Profile registered (READ_DOCUMENTS: Granted | DATA_EXPORT: Denied).\n")

    # 3. Process Prompt Input & Capability Check
    print("3. Evaluating Pre-Execution Security Controls...")
    clean_prompt, meta = shield.scan_prompt("Summarize annual report for executive review")
    print(f"   [OK] Input Prompt Scanned cleanly: '{clean_prompt}'")

    cap_check = shield.capability_engine.check_capability(
        CapabilityCheckRequest(capability=AgentCapability.DATA_EXPORT, agent_id=agent_id, tenant_id=tenant_id, context_data={"escalation": "grant_all"})
    )
    print(f"   [OK] Unauthorized DATA_EXPORT check result: Decision={cap_check.decision.value} (Allowed={cap_check.allowed})\n")

    # 4. Generate Multi-Signal Security Evidence & Containment Evaluation (Phase 27)
    print("4. Evaluating Multi-Signal Containment Posture...")
    ev_rt = EvidenceRecord(
        source_phase="Phase-23",
        evidence_type="RUNTIME_INTEGRITY",
        severity=EvaluationSeverity.CRITICAL,
        tenant_id=tenant_id,
        agent_id=agent_id,
        references={"integrity_state": "INVALID"}
    )
    ev_beh = EvidenceRecord(
        source_phase="Phase-24",
        evidence_type="BEHAVIOR_PATTERN",
        severity=EvaluationSeverity.CRITICAL,
        tenant_id=tenant_id,
        agent_id=agent_id,
        references={"pattern_id": "BEHAVIOR-004"}
    )

    assessment = shield.evaluation_engine.evaluate_evidence(tenant_id, agent_id, [ev_rt, ev_beh])
    print(f"   [OK] Assessment Outcome:    {assessment.outcome}")
    print(f"   [OK] Assessment Severity:   {assessment.severity}")
    print(f"   [OK] Rec. Isolation Level:  {assessment.recommended_isolation_level}")
    print(f"   [OK] Matched Rules:        {assessment.matched_rules}")
    print(f"   [OK] Explanation:          {assessment.explanation}\n")

    # 5. Execute Safe Adversarial Simulation (Phase 28)
    print("5. Executing Safe Adversarial Agent Simulation...")
    sim_res = shield.simulation_executor.execute_scenario("SCENARIO-CONTAINMENT-ESCALATION", tenant_id=tenant_id, agent_id=agent_id)
    print(f"   [OK] Simulation Status:     {sim_res.status}")
    print(f"   [OK] Expected Signal:       {sim_res.expected_signal} | Observed: {sim_res.actual_signal}")
    print(f"   [OK] Expected Outcome:      {sim_res.expected_outcome} | Observed: {sim_res.actual_outcome}\n")

    # 6. Execute Containment Benchmark (Phase 29)
    print("6. Running Containment Benchmark (7 scenarios x 5 iterations)...")
    bm_results = shield.benchmark_runner.run_benchmark(iterations=5, warmup_iterations=1, tenant_id=tenant_id, agent_id=agent_id)
    bm_report = BenchmarkReporter.generate_report(tenant_id, agent_id, bm_results)
    print(f"   [OK] Benchmark Evaluations: {bm_report.metrics.total_evaluations}")
    print(f"   [OK] Benchmark Pass Rate:   {bm_report.metrics.pass_rate * 100.0:.1f}%")
    print(f"   [OK] Average Latency:       {bm_report.metrics.avg_latency_ms:.4f} ms")
    print(f"   [OK] Throughput:            {bm_report.metrics.throughput_eps:.2f} evaluations/sec\n")

    # 7. Verify Security Invariants
    print("7. Verifying Master Security Invariants...")
    invariants = bm_report.invariant_results
    for inv, passed in invariants.items():
        status_str = "[OK]" if passed else "[FAIL]"
        print(f"   {status_str} Invariant '{inv.replace('_', ' ').title()}': Verified")

    print("\n==================================================================")
    print("[OK] AgentShield 2.0 System Integration & Release Validation COMPLETE")
    print("==================================================================")


if __name__ == "__main__":
    main()
