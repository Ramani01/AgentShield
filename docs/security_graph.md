# 🕸️ Agent Security Graph & Attack-Path Tracking (Phase 26)

## 📌 Purpose

The **Agent Security Graph & Attack-Path Tracking Engine** (`agentshield.graph`) provides a deterministic, graph-based observability and relationship analysis framework. It maps interactions between agents, principals, capabilities, tools, resources, memories, communication targets, behavioral events, and containment states.

> [!IMPORTANT]
> **Attack-Path Terminology Notice**: Attack-path tracking represents observed security-relevant relationships. A suspicious path is not by itself proof of malicious activity.

---

## 🎯 Threat Model & Terminology

An **attack-path** in AgentShield represents a security-relevant chain of observed relationships or events through which risk could propagate. The graph engine distinguishes between neutral classifications:
- `OBSERVED`: Standard relationship chain recorded during execution.
- `SUSPICIOUS`: Path involving high-risk capability usage, behavioral pattern triggers, or active containment.
- `UNKNOWN`: Unclassified path without baseline provenance.

The graph engine does **not** perform automated attribution or label paths as "malicious".

---

## 🏗️ Graph Architecture

```
Security Events (Phases 1–25)
              │
              ▼
     Graph Event Adapter        <── Ingests Capabilities, Tools, Behavior, Containment
              │
              ▼
    Canonical Graph Store       <── Enforces (Tenant ID, Agent ID) Boundaries
              │
              ▼
     Attack-Path Analyzer       <── Cycle-Safe Traversal & Path Discovery
              │
              ▼
     Security Path Assessment   <── Neutral Risk Signals & Evidence Preservation
```

---

## 🔒 Security Invariants

Phase 26 strictly enforces 12 non-negotiable security invariants:

| Invariant | Description |
| :--- | :--- |
| **Invariant 1 — Tenant Isolation** | Tenant A cannot query or observe Tenant B's security graph. Cross-tenant edges are strictly rejected. |
| **Invariant 2 — Agent Identity Isolation** | Shared tools/resources do not merge agent identities; agent nodes remain distinct. |
| **Invariant 3 — No Authorization Elevation** | Graph relationships cannot grant capabilities or elevate permissions. |
| **Invariant 4 — No Policy Override** | Graph analysis cannot override capability, communication, egress, containment, or runtime policies. |
| **Invariant 5 — Provenance Preservation** | Graph edges retain originating evidence, source controls, and timestamps. |
| **Invariant 6 — Deterministic Graph** | Identical event inputs produce identical graph structures. |
| **Invariant 7 — Deterministic Path Search** | Same graph and query inputs produce identical ordered paths. |
| **Invariant 8 — Bounded Traversal** | Path traversal depth is strictly capped (`max_depth`). |
| **Invariant 9 — Cycle Safety** | Cycles do not cause infinite loops during path traversal. |
| **Invariant 10 — No Unsupported Attribution** | Neutral classifications (`OBSERVED`, `SUSPICIOUS`, `UNKNOWN`) are enforced. |
| **Invariant 11 — No Cross-Agent Identity Collapse** | Different agents remain distinct graph nodes. |
| **Invariant 12 — Previous Controls Authoritative** | Controls 01–13 and Phases 21–25 remain authoritative. |

---

## 📄 Node & Edge Models

### Node Types (`NodeType`)
- `AGENT`, `PRINCIPAL`, `TENANT`, `CAPABILITY`, `TOOL`, `RESOURCE`, `MEMORY`, `COMMUNICATION_TARGET`, `BEHAVIOR_EVENT`, `BEHAVIOR_PATTERN`, `CONTAINMENT_STATE`, `CHECKPOINT`, `RUNTIME_STATE`.

### Edge Relationships (`RelationshipType`)
- `OWNS`, `AUTHORIZED_FOR`, `USES`, `ACCESSES`, `READS`, `WRITES`, `INVOKES`, `COMMUNICATES_WITH`, `PRODUCES`, `TRIGGERS`, `OBSERVED_DURING`, `CONTAINED_BY`, `RESTORED_FROM`, `DERIVED_FROM`, `CONNECTED_TO`.

---

## 🚀 Usage Example

```python
from agentshield import AgentShield
from agentshield.containment import IsolationLevel, ContainmentState

shield = AgentShield()

# 1. Ingest security events into graph
shield.graph_engine.ingest_capability_grant("tenant_a", "agent_007", "data:export")
shield.graph_engine.ingest_tool_invocation("tenant_a", "agent_007", "file_reader", resource="confidential.pdf")
shield.graph_engine.ingest_communication_event("tenant_a", "agent_007", "https://api.external.com")
shield.graph_engine.ingest_behavior_pattern_trigger("tenant_a", "agent_007", "BEHAVIOR-001", "Sensitive Data Escalation")

# 2. Discover and assess security paths
assessment = shield.graph_engine.find_agent_attack_paths("tenant_a", "agent_007")

print(f"Paths Discovered: {len(assessment.paths)}")
print(f"Risk Level: {assessment.risk_level}")
print(f"Signals: {assessment.signals}")
```
