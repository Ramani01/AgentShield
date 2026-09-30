"""
Synthetic Demonstration of AgentShield Phase 25 Emergency Containment.
"""

from agentshield import AgentShield
from agentshield.containment import IsolationLevel
from agentshield.behavior import BehaviorEventType


def run_containment_demo():
    print("=== AgentShield Phase 25 Emergency Containment Demo ===")
    shield = AgentShield()

    tenant_id = "enterprise_tenant"
    agent_id = "financial_analyst_agent"

    print(f"\n1. Initial Agent State: {shield.containment_manager.get_containment_status(tenant_id, agent_id)['current_state']}")

    # Check normal action
    d1 = shield.containment_manager.evaluate_action_gate(tenant_id, agent_id, BehaviorEventType.READ_DOCUMENT)
    print(f"   Normal READ_DOCUMENT action: Allowed={d1.allowed} ({d1.reason})")

    # 2. Trigger Emergency Containment
    print("\n2. Triggering Emergency Containment due to security alert...")
    record = shield.containment_manager.request_emergency_containment(
        tenant_id=tenant_id,
        agent_id=agent_id,
        reason="Detected suspicious prompt exfiltration pattern",
        severity="CRITICAL",
        isolation_level=IsolationLevel.FULL,
        principal_id="secops_monitor"
    )
    print(f"   New Agent State: {record.current_state} (Level: {record.isolation_level})")

    # 3. Test Action Gate Restrictions under FULL containment
    print("\n3. Testing Action Gate Enforcement under FULL Containment:")
    for action in [
        BehaviorEventType.READ_DOCUMENT,
        BehaviorEventType.DATA_EXPORT,
        BehaviorEventType.EXTERNAL_COMMUNICATION,
        BehaviorEventType.MODIFY_CONFIGURATION
    ]:
        d = shield.containment_manager.evaluate_action_gate(tenant_id, agent_id, action)
        status_str = "ALLOWED" if d.allowed else "BLOCKED"
        print(f"   Action '{action}': [{status_str}] -> {d.reason}")

    # 4. Initiate Controlled Recovery & Release
    print("\n4. Initiating Controlled Recovery by Authorized Governance Principal...")
    rec_res = shield.containment_manager.initiate_recovery(tenant_id, agent_id, principal_id="secops_admin")
    print(f"   Recovery Result: Success={rec_res['success']}, State={rec_res['state']}")

    rel_res = shield.containment_manager.release_containment(tenant_id, agent_id, principal_id="secops_admin")
    print(f"   Release Result: Success={rel_res['success']}, State={rel_res['state']}")

    final_status = shield.containment_manager.get_containment_status(tenant_id, agent_id)
    print(f"\n5. Final Agent State: {final_status['current_state']}")
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    run_containment_demo()
