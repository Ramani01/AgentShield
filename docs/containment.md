# 🚨 Agent Isolation & Emergency Containment (Phase 25)

## 📌 Purpose

The **Agent Isolation & Emergency Containment Module** (`agentshield.containment`) provides a stateful, framework-level defensive containment state machine and action gate. It transitions an AI agent from normal operation into restricted or monitored security states when security policy triggers or multi-step behavioral anomalies are detected.

> [!IMPORTANT]
> **Defensive Scope Notice**: Phase 25 provides framework-level defensive containment decisions and action restrictions. It does not perform operating-system process termination, infrastructure isolation, or destructive network control.

---

## 🎯 Threat Model

AgentShield Phase 25 limits agent operational authority during security incidents to prevent:
1. **Uncontrolled Data Exfiltration**: Blocking external communications and bulk data export when an agent is suspected or contained.
2. **Self-Configuration Tampering**: Blocking contained agents from mutating security policies or self-disabling containment controls.
3. **Escalated Tool Execution**: Restricting access to high-risk executable tools and system actions.
4. **Unauthorized Self-Release**: Requiring explicit administrative/governance principal authorization before restoring normal state.

---

## 🏗️ Architecture & State Machine

```
Security Events / Phase 24 Behavior / Phase 23 Integrity
                     │
                     ▼
             Containment Request
                     │
                     ▼
          Containment Policy Engine
                     │
                     ▼
           Isolation State Manager  <── Enforces (Tenant ID, Agent ID) Isolation
                     │
                     ▼
             Restricted Agent State
                     │
                     ▼
           Containment Action Gate  <── Restricts Action Execution
                     │
                     ▼
             Recovery / Release      <── Authorized Governance Principal
```

### State Machine Lifecycle
```
     NORMAL
       │  ▲
       │  │ (Released)
       ▼  │
    SUSPECTED
       │
       ▼
    CONTAINED
       │
       ▼
    RECOVERY
       │
       ▼
    RELEASED
```

---

## 🔒 Security Invariants

Phase 25 strictly enforces 12 security invariants:

| Invariant | Description |
| :--- | :--- |
| **Invariant 1 — Tenant Isolation** | Tenant A cannot contain, release, or alter Tenant B's agent state. |
| **Invariant 2 — Agent Isolation** | Agent A cannot alter Agent B's containment state. |
| **Invariant 3 — No Capability Elevation** | Containment can only restrict authority; it never grants capabilities. |
| **Invariant 4 — Containment Cannot Be Self-Disabled** | Contained agents cannot release themselves. |
| **Invariant 5 — Containment Policy Protection** | Contained agents cannot modify configuration or containment policy. |
| **Invariant 6 — Authorization Composition** | Final permission = `Existing Authorization AND Containment Permission`. |
| **Invariant 7 — Runtime Integrity** | Invalid or unknown runtime integrity prevents release from containment. |
| **Invariant 8 — Determinism** | Identical request + state produces identical decision outputs. |
| **Invariant 9 — Idempotency** | Repeated emergency containment requests are safe and idempotent. |
| **Invariant 10 — Valid State Transitions** | Invalid state machine transitions are strictly rejected. |
| **Invariant 11 — Audit Integrity** | All containment state changes and blocked actions generate tamper-evident audit records. |
| **Invariant 12 — Previous Controls Authoritative** | Controls 01–13 and Phases 21–24 remain authoritative. |

---

## 🛡️ Isolation Levels

1. **`NONE`**: Standard security operations.
2. **`MONITOR`**: Actions permitted with heightened audit logging.
3. **`RESTRICTED`**: High-risk actions (`MODIFY_CONFIGURATION`, `DATA_EXPORT`) blocked.
4. **`FULL`**: Non-essential actions (`MODIFY_CONFIGURATION`, `DATA_EXPORT`, `EXTERNAL_COMMUNICATION`, `USE_TOOL`, `EXECUTE_ACTION`, `WRITE_MEMORY`) blocked.

---

## 🚀 Usage Example

```python
from agentshield import AgentShield
from agentshield.containment import IsolationLevel
from agentshield.behavior import BehaviorEventType

shield = AgentShield()

# 1. Trigger emergency containment
shield.containment_manager.request_emergency_containment(
    tenant_id="tenant_alpha",
    agent_id="agent_007",
    reason="Anomalous exfiltration sequence detected",
    isolation_level=IsolationLevel.FULL
)

# 2. Action gate blocks restricted action
decision = shield.containment_manager.evaluate_action_gate(
    tenant_id="tenant_alpha",
    agent_id="agent_007",
    action_type=BehaviorEventType.DATA_EXPORT
)
print(f"Action Allowed: {decision.allowed} (Decision: {decision.decision})")

# 3. Governance recovery & release
shield.containment_manager.initiate_recovery("tenant_alpha", "agent_007", principal_id="admin_secops")
shield.containment_manager.release_containment("tenant_alpha", "agent_007", principal_id="admin_secops")
```
