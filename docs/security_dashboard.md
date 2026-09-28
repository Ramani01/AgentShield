# AgentShield Security Dashboard

## 1. Purpose

The AgentShield Security Dashboard provides a local, read-only security observability interface for AgentShield. It allows security engineers, developers, and reviewers to monitor and inspect:
- Security evaluation posture and control decisions
- Control-level results across all 13 AgentShield security controls
- Detailed security findings and recommendations
- Benchmark results and category coverage metrics from Phase 17
- Tool-change events and drift classification from Phase 14
- Checkpoint state and recovery events from Phase 15
- Tamper-evident audit activity and hash chain status
- Historical evaluation records

**Important Security Principle**: The Security Dashboard is purely a visualization and observability layer. It **NEVER** creates independent `ALLOW`, `DENY`, or `REVIEW` decisions, nor does it override decisions made by the core AgentShield security pipeline.

---

## 2. Architecture

```
AgentShield Security State
        ↓
SecurityPipeline / Evaluation Engine
        ↓
Dashboard Data Adapter (DashboardDataProvider)
        ↓
Dashboard REST API (FastAPI Router)
        ↓
Local Web UI (Single-Page App)
```

The dashboard queries live security state through `DashboardDataProvider`, which sanitizes and formats internal models before exposing them to the FastAPI endpoints. The web UI is a single-page HTML/CSS/JS interface served locally.

---

## 3. Dashboard Sections

1. **Overview**: Displays overall security status, latest decision timestamp, breakdown of control decisions (PASS/REVIEW/FAIL/ERROR), findings count, benchmark status, corpus version, and latest checkpoint state.
2. **Control Matrix**: Comprehensive table of all 13 security controls (`CONTROL-01` through `CONTROL-13`) displaying control ID, category, decision, severity, and last evaluation timestamp.
3. **Control Detail**: Deep-dive inspection view for individual controls showing status, decision, severity, sanitized evidence, findings, and evaluation context.
4. **Findings**: List of identified security findings filtered by severity, control ID, decision, or status.
5. **Benchmark**: Visualization of evaluation corpus benchmark results (Pass Rate, total cases, passed/failed, FP/FN candidates, execution timings).
6. **Tool Governance**: Tool change events, baseline fingerprints, current fingerprints, drift classification, and severity.
7. **Checkpoints**: Known-good security state checkpoints, state fingerprints, and creation timestamps.
8. **Audit Activity**: Tamper-evident audit log stream, event types, control references, and hash chain verification status.
9. **Evaluation History**: Read-only timeline of historical security evaluations.

---

## 4. API Endpoints

All API endpoints are strictly read-only (`GET` requests):

- `GET /api/dashboard/overview` — Overall security status & summary metrics
- `GET /api/dashboard/controls` — Status matrix for all 13 controls
- `GET /api/dashboard/controls/{control_id}` — Detail view for a specific control ID
- `GET /api/dashboard/findings` — Security findings list
- `GET /api/dashboard/benchmark` — Security benchmark execution summary
- `GET /api/dashboard/benchmark/categories` — Category-level benchmark breakdown
- `GET /api/dashboard/tools` — Tool governance state and drift events
- `GET /api/dashboard/checkpoints` — Checkpoint inventory and state fingerprints
- `GET /api/dashboard/audit` — Audit event logs and hash chain verification
- `GET /api/dashboard/evaluations` — Historical evaluation records

---

## 5. Data Provider

`DashboardDataProvider` acts as an adapter layer between internal AgentShield components (`SecurityEvaluationEngine`, `SecurityBenchmarkRunner`, `ToolGovernanceRegistry`, `CheckpointManager`, `AuditLogger`) and the dashboard API.

Responsibilities:
- `get_current_security_status()`
- `get_control_results()`
- `get_findings()`
- `get_latest_evaluation()`
- `get_benchmark_summary()`
- `get_tool_governance_events()`
- `get_checkpoint_events()`
- `get_audit_summary()`
- `get_evaluation_history()`

---

## 6. Security Boundaries

- **Read-Only**: The dashboard exposes zero mutation endpoints (`POST`, `PUT`, `DELETE`).
- **No Direct Action/Tool Execution**: The dashboard cannot invoke agent tools or trigger network requests on behalf of the agent.
- **Sanitized Outputs**: Evidence payloads are sanitized prior to JSON serialization.

---

## 7. Tenant Isolation

Dashboard queries pass through tenant-scoped contexts where applicable. `DashboardDataProvider` filters results to match the specified `tenant_id` context, preventing cross-tenant data leakage.

---

## 8. Authentication & Local-Only Behavior

- The dashboard binds to `127.0.0.1:8000` (localhost) by default.
- It is designated for **LOCAL DEVELOPMENT & REVIEW ONLY**.
- It does NOT introduce fake or hardcoded authentication credentials.
- When deployed in production environments, it must be protected by external API gateway authentication or reverse proxy authentication.

---

## 9. Evidence Sanitization

`DashboardDataProvider` automatically redacts sensitive data patterns prior to rendering:
- API keys, AWS credentials (`AKIA...`), GitHub tokens (`ghp_...`), JWTs, RSA keys
- Passwords and secret values
- Private memory contents and sensitive prompt payloads

---

## 10. Audit Display & Performance Hardening

The audit tab displays log activity recorded by `AuditLogger`.
- Displays event types, timestamps, control references, decisions, and severity.
- Computes and verifies the integrity of the tamper-evident SHA-256 hash chain.
- Audit logs remain immutable and read-only.
- **Performance Hardening**: Uses filesystem state-invalidation caching (`mtime_ns` and `st_size` tracking) to prevent re-hashing static audit log files on every request. Supports pagination and windowed event retrieval (`limit`, `offset`, `force_verify` query parameters) for low-latency (<200 ms) responses even on large multi-megabyte audit files.


---

## 11. Benchmark Display

- Benchmark performance is explicitly labeled **"Benchmark Pass Rate"**.
- Metrics displayed include: total benchmark cases (68), passed cases (68), failed cases (0), FP/FN candidates (0), execution time, and category breakdowns.
- **No Security Score**: Benchmark pass rate is never presented as a aggregate "Security Score" or "X% Secure" claim.

---

## 12. Tool Governance Display

Visualizes tool drift and baseline comparisons from Phase 14:
- Baseline fingerprints vs current fingerprints
- Changed tool fields
- Change classifications (`UNCHANGED`, `ADDED`, `MODIFIED`, `REVIEW`, `DENIED`)
- Severity and security decisions

---

## 13. Checkpoint Display

Visualizes security checkpoints from Phase 15:
- Checkpoint IDs, creation timestamps, and tenant scopes
- Checkpoint statuses (`ACTIVE`, `SUPERSEDED`, `REVOKED`, `RESTORED`)
- Deterministic state fingerprints
- **No Unrestricted Rollback**: The dashboard does not provide a rollback button; restoration must be performed via authenticated backend security APIs.

---

## 14. Evaluation History

Displays historical evaluation runs recorded by `SecurityEvaluationEngine`.
- Timestamps, evaluation IDs, total controls, findings count, and aggregated decision.
- Historical evaluation records are immutable and read-only.

---

## 15. Security Invariants

1. Dashboard does not create independent security decisions.
2. Dashboard displays existing evaluation decisions.
3. Dashboard cannot execute agent tools.
4. Dashboard cannot execute external network actions.
5. Dashboard does not expose secrets.
6. Dashboard does not expose private memory contents.
7. Dashboard respects tenant scope.
8. Historical evaluations are read-only.
9. Checkpoint records are read-only from the dashboard.
10. Tool governance data is read-only.
11. Audit logs are not modified by dashboard operations.
12. No unrestricted rollback endpoint is exposed.
13. Dashboard API errors do not leak stack traces.
14. Untrusted strings are safely escaped.
15. No hardcoded credentials are introduced.
16. Local-only mode is clearly documented when authentication is unavailable.
17. Benchmark pass rate is not presented as security score.
18. Control count does not imply control quality.
19. No control ranking is created.
20. Existing Phase 1–17 tests remain passing.

---

## 16. Limitations

- **Observability Layer Only**: The dashboard does not replace active security controls or governance enforcement.
- **Local Development Default**: Unauthenticated by default; must bind to localhost or behind secure proxy.
- **Memory Storage**: Evaluation history is stored in memory unless backed by persistent logger storage.

---

## 17. Local Startup Instructions

To start the local security dashboard server:

```bash
uvicorn agentshield.dashboard.app:app --host 127.0.0.1 --port 8000
```

Open a web browser and navigate to:
```
http://127.0.0.1:8000/
```
