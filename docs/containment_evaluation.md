# 🛡️ Phase 27: Containment Evaluation Engine

## Overview & Purpose

Phase 27 introduces a deterministic **Containment Evaluation Engine** to AgentShield 2.0. While Phase 25 provides the core containment manager and Phase 26 tracks graph attack paths, Phase 27 coordinates evidence from all security engines (Phases 21–26) and evaluates whether an observed security situation warrants containment, escalation, continued containment, recovery review, or release review.

> **CRITICAL DISCLAIMER:**  
> "Phase 27 evaluates containment evidence and produces deterministic recommendations. It does not independently perform containment release or operating-system-level isolation."

---

## 🏗️ Architecture

```
Security Signals
      │
      ├── Phase 23 Runtime Integrity
      ├── Phase 24 Behavioral Detection
      ├── Phase 25 Containment State
      └── Phase 26 Security Graph / Path Evidence
      │
      ▼
Containment Evidence Normalizer
      │
      ▼
Containment Evaluation Engine
      │
      ▼
Deterministic Policy Evaluation (RuleRegistry)
      │
      ▼
Containment Assessment
      │
      ├── MAINTAIN
      ├── ESCALATE
      ├── REVIEW
      ├── RELEASE_REVIEW
      └── NO_ACTION
      │
      ▼
Phase 25 Containment Manager (Authoritative Enforcement)
```

---

## 📊 Evidence Model & Normalization

Evidence is normalized into a canonical, tamper-resistant `EvidenceRecord`:

```python
@dataclass
class EvidenceRecord:
    evidence_id: str
    source_phase: str
    source_control: str
    evidence_type: str
    severity: str
    confidence: float
    tenant_id: str
    agent_id: str
    timestamp: float
    references: Dict[str, Any]
    freshness_status: str  # CURRENT | STALE
    metadata: Dict[str, Any]
```

### Supported Evidence Types
- `RUNTIME_INTEGRITY` (Phase 23: VALID, DRIFTED, INVALID, UNKNOWN)
- `BEHAVIOR_PATTERN` (Phase 24: risk levels LOW, MEDIUM, HIGH, CRITICAL)
- `CONTAINMENT_RECORD` (Phase 25: NORMAL, RESTRICTED, CONTAINED, RECOVERY)
- `SECURITY_GRAPH_PATH` (Phase 26: BENIGN, SUSPICIOUS, MALICIOUS)

---

## ⚖️ Evaluation Outcomes & Severity Model

### Assessment Outcomes (`EvaluationOutcome`)
1. `NO_ACTION`: Evidence indicates clean, baseline operating state.
2. `REVIEW`: Suspicious or unconfirmed risk signals warranting security review.
3. `MAINTAIN`: Agent already contained; ongoing risk signals justify maintaining active isolation.
4. `ESCALATE`: High or Critical severity threat sequence recommending immediate maximum isolation.
5. `RELEASE_REVIEW`: Agent is contained, runtime is valid, no unresolved risk signals exist, and a valid recovery request is pending.

### Deterministic Severity Levels (`EvaluationSeverity`)
`LOW < MEDIUM < HIGH < CRITICAL`

---

## ⚙️ Deterministic Rule Priority & Conflict Resolution

Rules are evaluated in strict priority order (lower numeric value = higher precedence):

| Priority | Rule ID | Rule Name | Target Outcome | Recommended Isolation |
|---|---|---|---|---|
| **10** | `RULE-001` | Critical Behavioral Evidence | `ESCALATE` | `FULL` |
| **20** | `RULE-002` | Invalid Runtime + Suspicious Behavior | `ESCALATE` | `FULL` |
| **25** | `RULE-002B`| High Behavioral Risk | `REVIEW` | `RESTRICTED` |
| **30** | `RULE-003` | Invalid Runtime Standalone | `ESCALATE` | `FULL` |
| **40** | `RULE-004` | Already Contained Agent Ongoing Risk | `MAINTAIN` | `FULL` |
| **50** | `RULE-005` | Suspicious Graph Path Evidence | `REVIEW` | `RESTRICTED` |
| **60** | `RULE-006` | Recovery Review Criteria Satisfied | `RELEASE_REVIEW` | `NONE` |
| **90** | `RULE-008` | Unresolved High/Critical Risk Signal | `REVIEW` | `RESTRICTED` |
| **100**| `RULE-007` | Clean State Baseline | `NO_ACTION` | `NONE` |

### Conflict Resolution Strategy
When conflicting security signals exist (e.g. Phase 23 returns `VALID` but Phase 24 returns `CRITICAL`), the higher precedence rule (`RULE-001` at Priority 10) takes precedence, ensuring critical behavioral indicators are never ignored due to valid runtime integrity.

---

## 🔎 Explainability & Audit Events

Every assessment generates a human-readable, evidence-linked explanation via `DecisionExplainer`.

### Audit Events Logged
- `CONTAINMENT_EVALUATION_STARTED`
- `CONTAINMENT_EVIDENCE_NORMALIZED`
- `CONTAINMENT_RULE_MATCHED`
- `CONTAINMENT_ASSESSMENT_CREATED`
- `CONTAINMENT_ESCALATION_RECOMMENDED`
- `CONTAINMENT_MAINTAIN_RECOMMENDED`
- `CONTAINMENT_RELEASE_REVIEW_RECOMMENDED`
- `CONTAINMENT_EVALUATION_ERROR`

---

## 🔒 Security Invariants Verified

1. **Tenant Isolation**: Tenant A evidence cannot influence Tenant B assessments.
2. **Agent Isolation**: Agent A evidence cannot influence Agent B assessments.
3. **No Capability Elevation**: Evaluation engine cannot grant or elevate capabilities.
4. **No Policy Override**: Phase 21–26 policies remain strictly authoritative.
5. **No Automatic Release**: Engine can produce `RELEASE_REVIEW`, but Phase 25 manages state changes.
6. **Deterministic Evaluation**: Identical evidence inputs produce identical assessments.
7. **Evidence Traceability**: Every non-`NO_ACTION` assessment cites supporting evidence IDs.
8. **No Unsupported Attribution**: Uses objective, evidence-backed explanations.
9. **Fail-Safe Error Handling**: Corrupted or malformed evidence safely resolves to `REVIEW`.
10. **Rule Priority Determinism**: Strict priority ordering avoids dictionary order dependencies.
11. **Previous Controls Authoritative**: Phases 1–26 remain fully frozen and enforced.

---

## 🧪 Benchmark Results

Deterministic synthetic benchmark measuring evidence evaluation performance across 1,000 multi-signal evaluation cycles:

- **Total Evaluations:** 1,000
- **Total Evidence Records Evaluated:** 3,000
- **Average Latency per Evaluation:** ~0.04 ms
- **Max Latency:** < 1.0 ms
- **Throughput:** > 25,000 evaluations / second

---

## ⚠️ Limitations

- Phase 27 provides recommendation metrics only; infrastructure enforcement requires integration with Phase 25 Containment Manager or external SOAR engines.
- Evidence freshness relies on synchronized system clocks or explicit synthetic timestamps.
