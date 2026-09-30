# 🧠 Multi-Step Behavioral Detection (Phase 24)

## 📌 Purpose

The **Multi-Step Behavioral Detection Engine** (`agentshield.behavior`) provides stateful, sequence-based detection of suspicious agent event chains across execution boundaries. 

While individual agent actions (such as reading a document, searching memory, or executing a tool) may pass single-action security checks, a specific **sequence** of individually permitted actions may indicate multi-step data exfiltration, tool abuse, or malicious configuration manipulation.

> [!IMPORTANT]
> **Detection Boundary Notice**: Behavioral detection identifies suspicious sequences but does not itself provide runtime containment. Containment and process isolation are handled in downstream security phases (Phase 25).

---

## 🎯 Threat Model

AgentShield Phase 24 defends against multi-step attack tactics where adversaries attempt to evade single-action filters:

1. **Sensitive Data Escalation**: Reading unvalidated retrieved documents, querying internal agent memory, and exporting combined context externally.
2. **Tool-to-Egress Chains**: Reading untrusted payloads, invoking executable tools, and immediately broadcasting payloads over external networks.
3. **Configuration-to-Egress Chains**: Tampering with agent security configurations, executing privileged tools, and opening unmonitored egress channels.
4. **Broad Data Exfiltration**: High-volume cross-source reads (memory & documents) followed by bulk data export and external communication.

---

## 🏗️ Architecture

```
Agent Security Events
        │
        ▼
Behavior Sequence Collector  <── Bounded, Isolated (Tenant ID, Agent ID)
        │
        ▼
Sequence Normalization       <── Canonical Serialization & SHA-256 Hashing
        │
        ▼
Behavior Pattern Analyzer    <── Subsequence Matching & Gap Enforcement
        │
        ▼
Behavior Risk Assessment     <── Severity Ranking & Recommendations
        │
        ▼
Behavior Decision / Recommendation (ALLOW / REVIEW / DENY)
```

The Behavioral Engine operates as a stateful observer running parallel to execution pipeline gates without altering baseline control decisions.

---

## 📄 Behavioral Event Model

Behavioral events (`BehaviorEvent`) capture normalized state transitions:

```python
@dataclass
class BehaviorEvent:
    event_id: str
    timestamp: float
    tenant_id: str
    agent_id: str
    principal_id: Optional[str]
    event_type: str
    resource: Optional[str]
    capability: Optional[str]
    communication_target: Optional[str]
    trust_level: Optional[str]
    runtime_integrity_state: Optional[str]
    source_control: Optional[str]
    metadata: Dict[str, Any]
```

### Standard Event Types (`BehaviorEventType`)
- `READ_DOCUMENT`: Agent retrieves or accesses external documents.
- `READ_MEMORY`: Agent queries short-term or long-term memory stores.
- `WRITE_MEMORY`: Agent persists information to memory.
- `USE_TOOL`: Agent invokes an integrated tool capability.
- `EXECUTE_ACTION`: Agent executes an external API action.
- `EXTERNAL_COMMUNICATION`: Agent sends payloads to external endpoints.
- `DATA_EXPORT`: Agent initiates bulk data export.
- `MODIFY_CONFIGURATION`: Agent mutates security or agent configuration.
- `CREATE_CHECKPOINT`: Agent snapshot creation.
- `ROLLBACK_CHECKPOINT`: Agent security rollback.

---

## 🔒 Security Invariants

Phase 24 strictly enforces 8 non-negotiable security invariants:

| Invariant | Description |
| :--- | :--- |
| **Invariant 1 — Tenant Isolation** | Events from different `tenant_id`s never combine into a sequence. |
| **Invariant 2 — Agent Isolation** | Events from different `agent_id`s never combine into a sequence. |
| **Invariant 3 — Detection ≠ Authorization** | Behavioral detection cannot grant or revoke agent capabilities (Phase 21 remains authoritative). |
| **Invariant 4 — Detection ≠ Containment** | Phase 24 provides detection and recommendations only; it does not perform process termination or container isolation. |
| **Invariant 5 — No Trust Elevation** | Untrusted context (`UNTRUSTED`, `UNKNOWN`) can never be elevated to `TRUSTED`. |
| **Invariant 6 — Determinism** | Identical sequences and pattern configurations produce identical `BehaviorAssessment` outputs. |
| **Invariant 7 — Bounded State** | Event sequence buffers per agent are strictly bounded (`max_sequence_length`). |
| **Invariant 8 — Previous Controls Authoritative** | Phase 24 cannot bypass Controls 01–13 or Phases 21–23. |

---

## ⚙️ Pattern Engine & Synthetic Detection Patterns

The `PatternRegistry` ships with built-in synthetic defensive patterns:

### Default Pattern Suite:
1. **`BEHAVIOR-001` Sensitive Data Escalation**:
   `READ_DOCUMENT -> READ_MEMORY -> DATA_EXPORT` (`HIGH` risk, `REVIEW` decision)
2. **`BEHAVIOR-002` Tool-to-Egress Chain**:
   `READ_DOCUMENT -> USE_TOOL -> EXTERNAL_COMMUNICATION` (`HIGH` risk, `REVIEW` decision)
3. **`BEHAVIOR-003` Configuration-to-Egress Chain**:
   `MODIFY_CONFIGURATION -> USE_TOOL -> EXTERNAL_COMMUNICATION` (`CRITICAL` risk, `DENY` decision)
4. **`BEHAVIOR-004` Broad Data Movement**:
   `READ_MEMORY -> READ_DOCUMENT -> DATA_EXPORT -> EXTERNAL_COMMUNICATION` (`CRITICAL` risk, `DENY` decision)
5. **`BEHAVIOR-005` Memory Tamper and Egress**:
   `WRITE_MEMORY -> MODIFY_CONFIGURATION -> EXTERNAL_COMMUNICATION` (`HIGH` risk, `REVIEW` decision)

---

## 🔌 Integration Summary

- **Phase 21 (Capability Engine)**: Behavioral events ingest capability identifiers as context without altering capability profiles.
- **Phase 22 (Communication Policy)**: Ingests principal, recipient target, and policy rules for contextual risk evaluation.
- **Phase 23 (Runtime Integrity)**: Ingests `runtime_integrity_state` and snapshot IDs without mutating baseline integrity states.
- **Audit Logging**: Emits tamper-evident log records (`BEHAVIOR_EVENT_RECORDED`, `BEHAVIOR_SEQUENCE_MATCH`, `BEHAVIOR_PATTERN_DETECTED`, `BEHAVIOR_REVIEW_REQUIRED`) chained with SHA-256 hashes.

---

## 🚀 Quick Usage Example

```python
from agentshield import AgentShield
from agentshield.behavior import BehaviorEventType

shield = AgentShield()

# Record agent actions in sequence
shield.behavior_engine.record_event(
    event_type=BehaviorEventType.READ_DOCUMENT,
    tenant_id="tenant_alpha",
    agent_id="agent_007"
)

shield.behavior_engine.record_event(
    event_type=BehaviorEventType.READ_MEMORY,
    tenant_id="tenant_alpha",
    agent_id="agent_007"
)

assessment = shield.behavior_engine.record_event(
    event_type=BehaviorEventType.DATA_EXPORT,
    tenant_id="tenant_alpha",
    agent_id="agent_007"
)

if assessment.matched:
    print(f"Pattern Detected: {assessment.pattern_name} ({assessment.risk_level})")
    print(f"Recommended Decision: {assessment.recommended_decision}")
```
