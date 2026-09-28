# AgentShield Security Benchmark & Evaluation Corpus (Phase 17)

## 1. Purpose

The purpose of the **AgentShield Security Benchmark & Evaluation Corpus** is to provide a structured, versioned framework of controlled security scenarios that systematically regression-test AgentShield's existing security controls (Controls 01 through 13).

The benchmark answers eight fundamental evaluation questions:
1. What security scenario was evaluated?
2. Which control was expected to handle it?
3. What decision was expected?
4. What decision did AgentShield produce?
5. Did the evaluation pass?
6. What evidence supports the result?
7. Which controls were exercised?
8. Were there candidate false positives or false negatives according to benchmark expectations?

---

## 2. Scope

The evaluation corpus tests all 13 AgentShield security controls:
- `CONTROL-01`: Instruction Isolation
- `CONTROL-02`: Trust Labeling
- `CONTROL-03`: Prompt Injection Defense
- `CONTROL-04`: Provenance & Data Lineage
- `CONTROL-05`: Permission-Aware Retrieval
- `CONTROL-06`: Context Integrity
- `CONTROL-07`: Memory Security
- `CONTROL-08`: Memory Write Gates
- `CONTROL-09`: Output & Action Validation
- `CONTROL-10`: Egress Control
- `CONTROL-11`: Token / Data Audience Control
- `CONTROL-12`: Tool-Change Detection & Review
- `CONTROL-13`: Security Checkpoint & Rollback

Everything operates on **SAFE LOCAL FIXTURES ONLY**. No real credentials, network calls, external tools, or attack infrastructure are used.

---

## 3. Corpus Structure

The initial corpus (`PRIMARY_BENCHMARK_CORPUS`, version `1.0.0`) consists of **68 structured benchmark cases** defined in [`agentshield/evaluation/benchmark_cases.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/evaluation/benchmark_cases.py).

Distribution:
- **Instruction Isolation**: 5 cases
- **Trust Labeling**: 5 cases
- **Prompt Injection Defense**: 8 cases
- **Provenance & Data Lineage**: 5 cases
- **Permission-Aware Retrieval**: 5 cases
- **Context Integrity**: 5 cases
- **Memory Security**: 5 cases
- **Memory Write Gates**: 5 cases
- **Output & Action Validation**: 5 cases
- **Egress Control**: 5 cases
- **Token / Data Audience Control**: 5 cases
- **Tool Change Detection**: 5 cases
- **Security Checkpoint / Rollback**: 5 cases

Total: **68 cases**

---

## 4. Case Model (`SecurityBenchmarkCase`)

Defined in [`agentshield/evaluation/benchmark_models.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/evaluation/benchmark_models.py):

| Field | Type | Description |
|-------|------|-------------|
| `case_id` | `str` | Stable ID (e.g. `AS-BENCH-001`) |
| `version` | `str` | Semantic version (default `1.0.0`) |
| `title` | `str` | Human-readable title |
| `description` | `str` | Detailed scenario description |
| `category` | `str` | Control category name |
| `target_control_ids` | `List[str]` | Applicable AgentShield control IDs |
| `scenario_type` | `ScenarioType` | `POSITIVE`, `NEGATIVE`, `REVIEW`, `BOUNDARY`, `REGRESSION` |
| `input_fixture` | `SecurityEvaluationContext` | Safe local evaluation context fixture |
| `expected_status` | `ControlStatus` | `PASS`, `FAIL`, `REVIEW`, `ERROR` |
| `expected_decision` | `SecurityDecision` | `ALLOW`, `DENY`, `REVIEW`, `ISOLATE` |
| `severity` | `ChangeSeverity` | Expected severity rating |
| `tags` | `List[str]` | Optional tagging metadata |

---

## 5. Case Categories

The 13 benchmark categories match AgentShield controls:
1. `Instruction Isolation` (`CONTROL-01`)
2. `Trust Labeling` (`CONTROL-02`)
3. `Prompt Injection Defense` (`CONTROL-03`)
4. `Provenance & Data Lineage` (`CONTROL-04`)
5. `Permission-Aware Retrieval` (`CONTROL-05`)
6. `Context Integrity` (`CONTROL-06`)
7. `Memory Security` (`CONTROL-07`)
8. `Memory Write Gates` (`CONTROL-08`)
9. `Output & Action Validation` (`CONTROL-09`)
10. `Egress Control` (`CONTROL-10`)
11. `Token / Data Audience Control` (`CONTROL-11`)
12. `Tool Change Detection` (`CONTROL-12`)
13. `Security Checkpoint / Rollback` (`CONTROL-13`)

---

## 6. Expected Outcomes

Every benchmark case explicitly specifies expected `expected_status` and `expected_decision`. Expected results are **never** dynamically inferred from `actual_result` (`expected = actual` is strictly prohibited to ensure independent regression detection).

---

## 7. Benchmark Runner (`SecurityBenchmarkRunner`)

Located in [`agentshield/evaluation/benchmark_runner.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/evaluation/benchmark_runner.py):

Responsibilities:
1. Loads `BenchmarkCorpus`.
2. Validates case definitions (`corpus.validate_corpus()`), failing closed if malformed.
3. Constructs local evaluation contexts.
4. Executes `SecurityEvaluationEngine.evaluate(fixture, pipeline)`.
5. Compares expected vs actual status and decision.
6. Identifies candidate False Positives & False Negatives.
7. Produces `SecurityBenchmarkReport`.

---

## 8. Result Model (`BenchmarkCaseResult` & `SecurityBenchmarkReport`)

- `BenchmarkCaseResult`: Stores case ID, expected/actual status & decision, `passed` boolean, candidate FP/FN flags, control results, findings, discrepancy string, and execution duration (`duration_ms`).
- `SecurityBenchmarkReport`: Aggregates total cases, passed/failed counts, pass rate percentage, false positive/negative counts, control & category summaries, total duration, and failed case IDs.

---

## 9. Coverage Metrics

Coverage is tracked across all 13 controls and 13 categories:
- `control_summary`: Number of total, passed, and failed cases per `CONTROL-01` .. `CONTROL-13`.
- `category_summary`: Total, passed, and failed cases per benchmark category.

> [!IMPORTANT]
> Control coverage count indicates test fixture depth, **not** security superiority. A control with more benchmark cases is not automatically "better".

---

## 10. False-Positive / False-Negative Terminology

These metrics are benchmark-relative findings:
- **Candidate False Positive**: AgentShield blocked/reviewed (`DENY`, `REVIEW`, `ISOLATE`) a scenario that the benchmark expects to allow (`ALLOW`).
- **Candidate False Negative**: AgentShield allowed (`ALLOW`) a scenario that the benchmark expects to block/review (`DENY`, `REVIEW`, `ISOLATE`).

---

## 11. Corpus Versioning

Corpus definitions are semantically versioned (e.g. `1.0.0`).
- Major version: Structural model changes or broad expectation policy shifts.
- Minor version: Addition of new benchmark cases.
- Patch version: Typo fixes or description updates without changing expectation contracts.

Case IDs remain stable across corpus versions.

---

## 12. Determinism

All test fixtures use deterministic local structures. Timestamps and execution durations are excluded from expected result comparisons to ensure 100% reproducible execution.

---

## 13. Security Boundaries

The benchmark engine **NEVER**:
- Makes network requests
- Scans external IP addresses or domains
- Invokes system shell commands
- Executes untrusted agent tools
- Reads real environment credentials or API tokens
- Generates real credential theft workflows

---

## 14. Phase 5 Corpus Compatibility

The benchmark maintains full compatibility with Phase 5's defensive injection corpus (`DEFENSIVE_EVAL_CORPUS` in [`agentshield/security/eval_corpus.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/security/eval_corpus.py)).

---

## 15. Security Invariants

1. `INVARIANT 1`: Every benchmark case has a stable ID (`AS-BENCH-xxx`).
2. `INVARIANT 2`: No duplicate case IDs exist in a corpus.
3. `INVARIANT 3`: Every case references valid control IDs (`CONTROL-01` .. `CONTROL-13`).
4. `INVARIANT 4`: Every case has an explicit expected result.
5. `INVARIANT 5`: Expected results are independent from actual evaluation results.
6. `INVARIANT 6`: Malformed benchmark cases are rejected fail-closed.
7. `INVARIANT 7`: Benchmark execution exercises `SecurityEvaluationEngine`.
8. `INVARIANT 8`: Benchmark cases do not execute external tools.
9. `INVARIANT 9`: Benchmark cases do not perform network activity.
10. `INVARIANT 10`: Secrets are not stored in benchmark fixtures.
11. `INVARIANT 11`: Private memory contents are not stored in benchmark fixtures.
12. `INVARIANT 12`: Repeated execution is deterministic.
13. `INVARIANT 13`: Benchmark pass rate is not represented as a universal security score.
14. `INVARIANT 14`: Control coverage does not imply control quality ranking.
15. `INVARIANT 15`: Benchmark reports preserve failed case IDs.
16. `INVARIANT 16`: Corpus version is recorded.
17. `INVARIANT 17`: Existing Phase 5 injection cases remain compatible.
18. `INVARIANT 18`: Existing Phases 1–16 tests remain passing.

---

## 16. Limitations

- The corpus tests AgentShield's implemented security controls under local fixture conditions.
- Pass rate reflects internal regression consistency, **not** immunity against unknown zero-day attack vectors.
- Does not replace continuous red-teaming or external security auditing.

---

## 17. How to Add a New Benchmark Case

To add a new benchmark case to `PRIMARY_BENCHMARK_CORPUS`:

1. Open [`agentshield/evaluation/benchmark_cases.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/evaluation/benchmark_cases.py).
2. Construct a `SecurityBenchmarkCase`:
```python
SecurityBenchmarkCase(
    case_id="AS-BENCH-069",
    title="New Security Scenario",
    description="Description of the test scenario",
    category="Instruction Isolation",
    target_control_ids=["CONTROL-01"],
    scenario_type=ScenarioType.NEGATIVE,
    input_fixture=SecurityEvaluationContext(
        scope=EvaluationScope.CONTEXT,
        context_items=[...]
    ),
    expected_status=ControlStatus.FAIL,
    expected_decision=SecurityDecision.DENY,
    severity=ChangeSeverity.HIGH
)
```
3. Append the new case to `_CASES`.
4. Run pytest to verify: `python -m pytest tests/unit/test_security_benchmark.py`.
