# 🛡️ Phase 28: Safe Adversarial Agent Simulation

## Overview & Purpose

Phase 28 introduces a **Safe Adversarial Agent Simulation Framework** to AgentShield 2.0. The framework generates controlled, synthetic, non-destructive adversarial security scenarios and evaluates how AgentShield's active security pipeline (Phases 21–27) responds.

> **CRITICAL SAFETY DISCLAIMER:**  
> "Phase 28 performs controlled simulation only. It does not execute real adversarial actions, shell commands, network attacks, or modify infrastructure."

---

## 🏗️ Architecture

```
Adversarial Scenario Registry (ScenarioRegistry)
      │
      ├── SCENARIO-CAPABILITY-ESCALATION
      ├── SCENARIO-POLICY-DENIAL
      ├── SCENARIO-BEHAVIORAL-RISK
      ├── SCENARIO-RUNTIME-DRIFT
      ├── SCENARIO-GRAPH-RISK
      ├── SCENARIO-CONTAINMENT-ESCALATION
      └── SCENARIO-RECOVERY-REVIEW
      │
      ▼
Deterministic Event Generator (SimulationGenerator)
      │
      ▼ (simulation_only = True)
Safe Simulation Executor (SimulationExecutor)
      │
      ├── Phase 21 Capability Engine
      ├── Phase 22 Communication Policy
      ├── Phase 23 Runtime Integrity
      ├── Phase 24 Behavioral Detection
      ├── Phase 25 Containment Manager (Read-Only Status)
      ├── Phase 26 Security Graph
      └── Phase 27 Containment Evaluation Engine
      │
      ▼
Expected vs. Actual Evaluator (SimulationEvaluator)
      │
      ▼
Audit Report Generator (SimulationReportGenerator)
```

---

## 🔒 Safety Boundaries

1. **No Shell Execution:** Never invokes `subprocess`, `os.system`, shell commands, or arbitrary scripts.
2. **No Network Calls:** Executes entirely in-memory without external sockets, HTTP calls, or web requests.
3. **No Infrastructure Modification:** Does not alter OS isolation, firewalls, process tables, or containers.
4. **No Capability Elevation:** Does not grant agent capabilities in `CapabilityEngine`.
5. **No Automatic State Change:** Does not perform actual containment state transitions or release in `ContainmentManager`.
6. **Simulation Only Marker:** Every synthetic event strictly specifies `simulation_only = True`.

---

## 📋 Registered Scenarios

| Scenario ID | Target Phase | Description | Expected Signal | Expected Outcome | Expected Isolation |
|---|---|---|---|---|---|
| `SCENARIO-CAPABILITY-ESCALATION` | Phase 21 | Agent requests ungranted `DATA_EXPORT` capability | `CAPABILITY_DENIED` | `REVIEW` | `RESTRICTED` |
| `SCENARIO-POLICY-DENIAL` | Phase 22 | Repeated outbound requests to untrusted targets | `COMMUNICATION_DENY` | `REVIEW` | `RESTRICTED` |
| `SCENARIO-BEHAVIORAL-RISK` | Phase 24 | Synthetic critical behavioral risk sequence | `BEHAVIOR_PATTERN_MATCH` | `ESCALATE` | `FULL` |
| `SCENARIO-RUNTIME-DRIFT` | Phase 23 | Synthetic `INVALID` runtime integrity check | `RUNTIME_INTEGRITY_INVALID` | `ESCALATE` | `FULL` |
| `SCENARIO-GRAPH-RISK` | Phase 26 | Synthetic suspicious attack path signal | `SECURITY_GRAPH_PATH_SUSPICIOUS` | `REVIEW` | `RESTRICTED` |
| `SCENARIO-CONTAINMENT-ESCALATION` | Phase 27 | Combined invalid runtime + critical behavior | `CONTAINMENT_ESCALATE_RECOMMENDED` | `ESCALATE` | `FULL` |
| `SCENARIO-RECOVERY-REVIEW` | Phase 27 | Contained agent + valid runtime + recovery request | `CONTAINMENT_RELEASE_REVIEW_RECOMMENDED` | `RELEASE_REVIEW` | `NONE` |

---

## 📊 Evaluation Lifecycle

1. **Registration:** Scenarios are statically defined and registered in `ScenarioRegistry`.
2. **Event Generation:** `SimulationGenerator` produces concrete `SimulationEvent` streams bound to `(tenant_id, agent_id)`.
3. **Safe Execution:** `SimulationExecutor` passes synthetic events to AgentShield engines and captures actual signals/decisions.
4. **Verification:** `SimulationEvaluator` compares `expected_signal` and `expected_outcome` against `actual_signal` and `actual_outcome`.
5. **Reporting:** `SimulationReportGenerator` compiles an audit-friendly `SimulationReport`.

---

## 🔒 Security Invariants Enforced

1. **Tenant Isolation:** Synthetic events for Tenant A cannot affect Tenant B evaluation.
2. **Agent Isolation:** Synthetic events for Agent A cannot affect Agent B evaluation.
3. **No Capability Modification:** Capability grants in Phase 21 remain untouched.
4. **No Containment Override:** Containment state in Phase 25 remains authoritative and unbypassed.
5. **Deterministic Results:** Same scenario + tenant + agent + seed = identical simulation results.
6. **No Unsupported Claims:** Results capture exact evidence IDs, matched rule IDs, and step details.

---

## 🧪 Benchmark & Performance

Deterministic synthetic benchmark measuring simulation execution latency across 100 full scenario suites:

- **Suite Size:** 7 scenarios / cycle
- **Total Executions:** 700 simulations
- **Average Latency per Scenario:** ~0.15 ms
- **Throughput:** > 6,500 scenario executions / second

---

## ⚠️ Limitations

- Phase 28 generates synthetic signals in-memory; it does not replace live threat detection during real-world agent execution.
- Release review simulation verifies recommendation logic, but Phase 25 retains sole authorization for performing actual agent recovery.
