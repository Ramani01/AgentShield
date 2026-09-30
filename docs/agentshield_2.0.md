# 🛡️ AgentShield 2.0 — Comprehensive System Documentation

## Executive Overview
AgentShield 2.0 is an enterprise-grade, defense-in-depth security, safety, and governance framework for Autonomous AI Agents and Multi-Agent Workflows.

The framework provides an end-to-end security architecture covering prompt scanning, context integrity, least-privilege capability controls, communication policy enforcement, runtime environment integrity, behavioral detection, topological attack-path modeling, containment evaluation recommendations, safe adversarial simulation, and statistical containment benchmarking.

---

## 🏗️ End-to-End Security Architecture

```
Agent Request / User Input
      │
      ▼
Prompt Injection & Jailbreak Defense (Phases 1-5)
      │
      ▼
Context Integrity & Instruction Isolation (Phases 6-10)
      │
      ▼
Capability Enforcement Engine (Phase 21)
      │
      ▼
Communication & Egress Policy Engine (Phase 22)
      │
      ▼
Runtime Environment Integrity Engine (Phase 23)
      │
      ▼
Behavioral Sequence Detection Engine (Phase 24)
      │
      ▼
Security Graph & Attack Path Engine (Phase 26)
      │
      ▼
Containment Manager & Action Gate (Phase 25)
      │
      ▼
Containment Evaluation Engine (Phase 27)
      │
      ├── Safe Adversarial Simulation (Phase 28)
      └── Containment Benchmark Framework (Phase 29)
      │
      ▼
Audit Logger & Lineage Provenance (Phases 11-20)
```

---

## 🔑 Phase Authorities & Responsibilities

- **Phase 21 (Capability Engine):** Authoritative for least-privilege agent capability profiles (`READ_DOCUMENTS`, `USE_TOOLS`, `DATA_EXPORT`, etc.).
- **Phase 22 (Communication Policy Engine):** Authoritative for inter-principal (agent-to-agent, agent-to-service) communication rules and egress policy.
- **Phase 23 (Runtime Integrity Engine):** Authoritative for runtime environment integrity state (`VALID`, `DRIFTED`, `INVALID`, `UNKNOWN`).
- **Phase 24 (Behavioral Detection Engine):** Authoritative for sequence detection and behavioral risk pattern classification (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Phase 25 (Containment Manager):** Authoritative for actual agent containment state transitions (`NORMAL`, `RESTRICTED`, `CONTAINED`, `RECOVERY`) and emergency isolation.
- **Phase 26 (Security Graph Engine):** Authoritative for graph modeling, node relationships, and attack-path risk signals.
- **Phase 27 (Containment Evaluation Engine):** Coordinates evidence across Phases 21–26 and outputs deterministic containment recommendations (`NO_ACTION`, `REVIEW`, `MAINTAIN`, `ESCALATE`, `RELEASE_REVIEW`).
- **Phase 28 (Safe Adversarial Simulation):** Executes safe, in-memory synthetic scenario simulations with `simulation_only = True`.
- **Phase 29 (Containment Benchmark):** Measures correctness, latency percentiles, and throughput of the security pipeline without enforcement side effects.
- **Phase 30 (System Validation & Release):** End-to-End integration testing, invariant master validation, and documentation.

---

## 🔒 Security Invariants & Guarantees

1. **Tenant & Agent Isolation:** Multi-tenant evidence boundaries strictly prevent cross-tenant or cross-agent evidence leakage.
2. **Authoritative Boundaries:** Lower-level security decisions (`DENY`, `INVALID`, `CONTAINED`) cannot be overridden by higher-level evaluation or simulation tools.
3. **No Automatic Containment Release:** `RELEASE_REVIEW` recommendations require explicit administrative authorization through Phase 25.
4. **Determinism:** Identical security inputs and evidence produce identical evaluation decisions.
5. **Traceability:** All security assessments retain clickable evidence IDs and audit logs.
6. **Safety:** All simulation events run 100% in-memory without subprocesses or network calls.

---

## 🚀 Quickstart Usage

```python
from agentshield import AgentShield

# Initialize AgentShield facade
shield = AgentShield()

# 1. Scan prompt for threats
clean_prompt, meta = shield.scan_prompt("User query text")

# 2. Evaluate containment posture for agent
assessment = shield.evaluation_engine.evaluate_agent(tenant_id="tenant_x", agent_id="agent_007")
print(f"Assessment Outcome: {assessment.outcome} | Recommended Isolation: {assessment.recommended_isolation_level}")

# 3. Run safe simulation scenario
sim_result = shield.simulation_executor.execute_scenario("SCENARIO-CONTAINMENT-ESCALATION", tenant_id="tenant_x", agent_id="agent_007")
print(f"Simulation Result: {sim_result.status}")

# 4. Run containment benchmark
bm_results = shield.benchmark_runner.run_benchmark(iterations=10, tenant_id="tenant_x", agent_id="agent_007")
print(f"Benchmark Evaluations: {len(bm_results)}")
```
