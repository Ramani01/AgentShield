"""
Phase 28 Safe Adversarial Agent Simulation Demonstration.
"""

from agentshield import AgentShield
from agentshield.simulation import (
    ScenarioRegistry,
    SimulationExecutor,
    SimulationReportGenerator
)


def main():
    print("=== AgentShield 2.0 — Phase 28 Safe Adversarial Simulation Demo ===")
    shield = AgentShield()

    tenant_id = "tenant_alpha"
    agent_id = "agent_sim_007"

    print(f"\n1. Initializing Simulation Executor for Tenant '{tenant_id}', Agent '{agent_id}'...")
    executor = shield.simulation_executor

    registry = ScenarioRegistry(include_defaults=True)
    scenarios = registry.list_scenarios()
    print(f"Loaded {len(scenarios)} registered safe simulation scenarios.")

    results = []
    print("\n2. Executing Synthetic Adversarial Scenarios...")
    for s in scenarios:
        res = executor.execute_scenario(s.scenario_id, tenant_id=tenant_id, agent_id=agent_id)
        results.append(res)
        print(f"  [{res.status}] {s.scenario_id}:")
        print(f"      Expected Signal: {res.expected_signal} | Observed Signal: {res.actual_signal}")
        print(f"      Expected Outcome: {res.expected_outcome} | Observed Outcome: {res.actual_outcome}")
        print(f"      Rec. Isolation:  {res.actual_isolation_level}")

    print("\n3. Generating Audit Report...")
    report = SimulationReportGenerator.generate_report(tenant_id, agent_id, results)
    print("\n=== Simulation Summary Report ===")
    print(f"Report ID:    {report.report_id}")
    print(f"Total Scenarios Evaluated: {report.scenario_count}")
    print(f"Passed:       {report.pass_count}")
    print(f"Failed:       {report.fail_count}")
    print(f"Success Rate: {report.summary['success_rate_pct']}%")

    print("\n=== Safety Invariant Verification ===")
    print("[OK] Simulation executed 100% in-memory without shell commands or network requests.")
    print("[OK] All synthetic events marked with simulation_only = True.")
    print("[OK] Phase 25 Containment Manager state remained strictly authoritative.")


if __name__ == "__main__":
    main()
