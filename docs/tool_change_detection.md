# Phase 14 — Tool-Change Detection & Review

## 1. Purpose
AgentShield's Tool-Change Detection & Review module ensures that AI agents **do not silently operate with an unexpectedly changed tool definition or tool security profile**. By detecting definition drift, schema alterations, capability inflation, and identity tampering before execution, AgentShield provides change governance and integrity assurance.

## 2. Threat Model
- **Silent Tool Definition Drift**: Adversaries or rogue tool servers alter input/output schemas or metadata without notice to trick agents into releasing unauthorized data or accepting dangerous input formats.
- **Capability Inflation**: A tool previously approved for read-only actions quietly gains write/execution capabilities while retaining baseline approval.
- **Identity Hijacking / Confusion**: A tool description claims to be another tool (`tool_id` manipulation or spoofing) to bypass policy gates.
- **Unauthorized Schema Expansion**: Additional parameters (e.g. `admin: boolean`) are appended to tool input schemas to escalate privileges during execution.

## 3. Tool Definition Model
`ToolDefinition` represents a tool's declared interface and security metadata:
- `tool_id`: Unique structural identifier of the tool.
- `name`: Display name of the tool.
- `version`: Version identifier string (e.g. `1.0.0`).
- `description`: Textual documentation of tool purpose.
- `input_schema`: JSON schema dict defining allowed input arguments.
- `output_schema`: JSON schema dict defining return data structures.
- `capabilities`: List of capability labels (e.g. `["read", "write"]`).
- `security_metadata`: Dict specifying security properties (e.g. required roles, isolation constraints).
- `provenance_id`: Optional identifier linking to the origin of the tool definition.
- `metadata`: Arbitrary key-value metadata.

## 4. Fingerprinting
Tool fingerprints are computed deterministically using SHA-256 over normalized tool definition payloads (`compute_tool_fingerprint`).

> [!IMPORTANT]
> **VALID FINGERPRINT != TRUSTED TOOL**
> A valid fingerprint proves that a tool definition matches a recorded baseline. It does **NOT** imply that the tool itself is safe or trusted.

## 5. Normalization
Before fingerprint calculation, `normalize_tool_definition` performs deterministic normalization to prevent false-positive alerts caused by formatting differences:
- Recursive dictionary key sorting (`sort_keys=True`).
- Primitive list element sorting (e.g., capabilities list `["write", "read"]` $\rightarrow$ `["read", "write"]`).
- Whitespace collapsing and trimming on string descriptions and names (`re.sub(r"\s+", " ", text)`).
- Preservation of all security-relevant fields and schema types.

## 6. Baselines
A `ToolBaseline` records the approved tool fingerprint, version, definition, and creation timestamp:
- `ToolGovernanceRegistry.register_baseline()` records an initial approved state.
- Newly observed tools without a baseline are **NOT** automatically approved; they receive a `SecurityDecision.REVIEW` result.

## 7. Change Classification
AgentShield categorizes tool changes into four deterministic severity tiers:
- **`LOW`**: Description-only changes.
- **`MEDIUM`**: Version changes, provenance ID updates, or initial registration of unknown tools.
- **`HIGH`**: Input schema alterations, output schema alterations, or display name changes.
- **`CRITICAL`**: Capability inflation/alteration, security metadata changes, or structural `tool_id` identity mismatches.

## 8. Security-Sensitive Changes
Changes to capabilities, security metadata, input schemas, output schemas, and identity are treated as high/critical severity. A changed tool definition **never silently inherits previous approval**.

## 9. Tool Identity
Tool identity is strictly bound to the `tool_id` field in `ToolDefinition`. Free-text descriptions or tool metadata cannot redefine or override `tool_id`.

## 10. Version Changes
Version updates are detected and classified as `MEDIUM` severity. Version bumps require explicit governance review (`REVIEW`) and do not automatically cause total denial unless accompanied by unauthorized capability or identity tampering.

## 11. Schema Changes
Drift in `input_schema` or `output_schema` is detected as `HIGH` severity. Unapproved schema changes return `SecurityDecision.REVIEW` and prevent execution.

## 12. Capability Changes
Modifications to `capabilities` (e.g., gaining `"execute"` or `"net_egress"`) trigger `CRITICAL` severity and require administrative review.

## 13. Security Metadata Changes
Alterations to `security_metadata` (such as required authorization roles or risk ratings) trigger `CRITICAL` severity and block execution pending review.

## 14. Provenance
`ToolDefinition.provenance_id` links the tool definition to its origin tracking record. Provenance changes are detected and audited.

> [!IMPORTANT]
> **VALID PROVENANCE != TRUSTED TOOL**
> Provenance records where a tool definition originated. It does not automatically grant trust or bypass authorization.

## 15. Change Review Policy
The governance policy maps detected changes to security decisions:
- **Unchanged Tool**: `SecurityDecision.ALLOW`
- **Description-only Change**: `SecurityDecision.ALLOW` (default low-risk policy)
- **Version / Provenance / New Tool**: `SecurityDecision.REVIEW`
- **Input / Output Schema Change**: `SecurityDecision.REVIEW`
- **Capability / Security Metadata Change**: `SecurityDecision.REVIEW`
- **Identity Mismatch / Hijack**: `SecurityDecision.DENY`

## 16. Baseline Approval
Baselines are updated **only through explicit administrative calls** (`approve_tool_change()`). Detected changes never overwrite existing baselines automatically.

## 17. Audit Behavior
All governance events are logged using `AuditLogger` with SHA-256 hash chaining:
- `TOOL_BASELINE_REGISTERED`
- `TOOL_CHANGE_ALLOWED`
- `TOOL_CHANGE_REVIEW`
- `TOOL_CHANGE_BLOCKED`
- `TOOL_CHANGE_APPROVED`
Private payload values or secrets in schemas are redacted before logging.

## 18. Pipeline Integration
`SecurityPipeline` exposes `validate_tool_change()` and `approve_tool_change()`. In strict policy mode (`strict_policy_mode=True`), any `SecurityDecision.DENY` raises a `SecurityViolationError`. Tools are analyzed purely as static definitions and are **never executed** during change analysis.

## 19. Security Invariants
1. Equivalent normalized tool definitions produce identical fingerprints.
2. Security-relevant changes alter the fingerprint.
3. Valid fingerprint does not imply trusted tool.
4. Valid provenance does not imply trusted tool.
5. Version change is detected.
6. Input schema change is detected.
7. Output schema change is detected.
8. Capability change is detected.
9. Security metadata change is detected.
10. Tool identity change is detected.
11. Description cannot redefine tool identity.
12. New tools without a baseline require review.
13. Security-sensitive changes require review or denial.
14. Detected changes do not automatically overwrite baselines.
15. Approved changes update the baseline.
16. Rejected changes do not update the baseline.
17. Tool provenance is preserved.
18. Tool authorization is separate from tool integrity.
19. Change decisions are auditable via tamper-evident logs.
20. Tool definitions are not executed during change analysis.

## 20. Relationship to SecureMCP
- **SecureMCP**: Responsible for runtime transport security, MCP server verification, session binding, tool allowlisting, and runtime authorization.
- **AgentShield Phase 14**: Responsible for static tool definition integrity, deterministic fingerprinting, schema drift detection, capability governance, and baseline change management.
- **Separation**: AgentShield Phase 14 complements SecureMCP and does not replace or duplicate MCP authorization, allowlisting, or transport isolation.

## 21. Limitations
- AgentShield analyzes static tool definitions; runtime server behavior anomalies must be governed by SecureMCP runtime controls.
- Phase 14 baseline state is stored in the local registry (`ToolGovernanceRegistry`). Distributed multi-node synchronization will build on this model in future releases.
- Phase 14 does not implement checkpoint/rollback (deferred to Phase 15).

## 22. Test Coverage
- **Fingerprint Tests (A–I)**: Normalization, dictionary key ordering, schema/capability changes.
- **Baseline Tests (J–L)**: Initial registration, unchanged comparison, new tool review.
- **Change Detection (M–T)**: Version, description, input schema, output schema, capability, security metadata, identity, and provenance drift.
- **Governance & Policy (U–Z)**: Severity classification, baseline updating, approval vs rejection.
- **Security Separation (AA–AD)**: Fingerprint/provenance non-trust, description non-identity.
- **Audit Logging (AE–AG)**: Event emission, tamper-evident log integrity, secret redaction.
- **Pipeline Integration (AH–AL)**: `SecurityPipeline` methods, strict policy enforcement, non-interference with SecureMCP.
- **Negative Security Tests**: Refutation of false security assumptions (e.g. `valid fingerprint == trusted tool`).
