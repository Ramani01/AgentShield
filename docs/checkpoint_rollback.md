# Phase 15 — Security Checkpoint & Rollback

## 1. Purpose
AgentShield's Security Checkpoint & Rollback module enables the creation of immutable security configuration snapshots (`SecurityCheckpoint`) and governs safe, authorized restoration (`RollbackRequest`) when a subsequent security state or tool definition change is determined to be unsafe.

> [!IMPORTANT]
> **CORE SECURITY INVARIANT**
> AN UNTRUSTED OR UNSAFE SECURITY STATE MUST NOT BECOME PERMANENT MERELY BECAUSE IT WAS APPLIED AFTER A PREVIOUSLY APPROVED STATE.

## 2. Scope
Phase 15 provides **AgentShield Security-State Checkpoint and Recovery**.

> [!WARNING]
> **WHAT PHASE 15 DOES NOT PROVIDE**
> Phase 15 does **NOT** provide:
> - Database disaster recovery
> - Application data backup / restore
> - Infrastructure / VM snapshotting
> - Operating system rollback
> - Arbitrary user file restoration
> - External service or MCP runtime server recovery

## 3. Security-State Definition
Only security-relevant configuration states are checkpointed:
- Tool baselines (`Dict[str, ToolBaseline]`)
- Security policy rules and snapshots (`policy_snapshot`)
- AgentShield security settings (`configuration_snapshot`)
- Provenance references (`provenance_id`)

Raw credentials, secrets, passwords, API keys, arbitrary databases, and raw private memory contents are explicitly excluded and sanitized from checkpoints.

## 4. Checkpoint Model
`SecurityCheckpoint` represents an immutable security state snapshot:
- `checkpoint_id`: Unique identifier (e.g. `chk_a1b2c3d4e5f6`).
- `created_at`: Creation epoch timestamp.
- `created_by`: Principal ID that created the checkpoint.
- `tenant_id`: Tenant scope identifier.
- `description`: Textual description of security state.
- `state_fingerprint`: Deterministic SHA-256 fingerprint.
- `tool_baselines`: Recorded `ToolBaseline` dictionary.
- `policy_snapshot`: Policy rules dict.
- `configuration_snapshot`: AgentShield configuration settings.
- `provenance_id`: Optional lineage reference.
- `metadata`: Arbitrary sanitized metadata.
- `status`: Enum (`ACTIVE`, `SUPERSEDED`, `REVOKED`, `RESTORED`).

## 5. Fingerprinting
`compute_checkpoint_fingerprint` generates a SHA-256 state fingerprint over canonicalized tool baselines, policy snapshot, configuration snapshot, and tenant ID.

> [!IMPORTANT]
> **CHECKPOINT FINGERPRINT != TRUST**
> A valid checkpoint fingerprint proves that the checkpoint representation has not been tampered with or corrupted. It does **NOT** prove that the underlying security state is inherently safe or authorized.

## 6. Integrity Validation
`CheckpointManager.validate_checkpoint()` verifies:
- Checkpoint exists in store.
- Structural completeness and field validity.
- Re-computed state fingerprint matches `checkpoint.state_fingerprint`.
- Absence of unredacted credentials or corrupted payloads.

If validation fails, the decision is `SecurityDecision.DENY`, and an audit event `CHECKPOINT_INVALID` is logged.

## 7. Immutability
Once created, `SecurityCheckpoint` objects are strictly immutable. Calls to `get_checkpoint()` and `list_checkpoints()` return deep copies. Normal code paths cannot mutate recorded baselines or state fingerprints. Applying new security states creates a new distinct checkpoint.

## 8. Authorization
Rollback is a privileged security operation:
- Anonymous or unauthenticated rollback requests are rejected (`SecurityDecision.DENY`).
- Requester identity (`UserIdentity`) must possess an authorized role (`"admin"`, `"security_admin"`, or `"system"`).
- Requester identity `user_id` must match `request.requested_by`.

## 9. Tenant Isolation
Checkpoints are strictly scoped to a single `tenant_id`.
- Tenant A checkpoints **cannot** be restored into Tenant B.
- Identity tenant scope (`identity.tenant_id`) must match both the request tenant and the checkpoint tenant.

## 10. Rollback Request
`RollbackRequest` captures explicit intent:
- `checkpoint_id`: Target checkpoint ID.
- `requested_by`: Requester user ID.
- `tenant_id`: Target tenant ID.
- `reason`: Rationale for rollback.
- `authorization_context`: Additional security claims.
- `requested_at`: Request timestamp.

Rollback is **never** executed automatically merely because a tool drift or policy change is detected.

## 11. Rollback Workflow
1. **Audit Request**: Log `ROLLBACK_REQUESTED`.
2. **Authorization & Tenant Isolation**: Verify identity presence, roles, and tenant matching.
3. **Checkpoint Verification**: Retrieve target checkpoint and run `validate_checkpoint()`.
4. **Current State Protection**: Capture current tool baselines and compute `previous_state_fingerprint`.
5. **State Restoration**: Apply `registry.restore_baselines()` and update policy engine/config state.
6. **Post-Rollback Validation**: Re-export restored state, recompute state fingerprint, and verify `restored_state_fingerprint == checkpoint.state_fingerprint`.
7. **Audit & Finalize**: Log `ROLLBACK_COMPLETED` and update checkpoint status to `RESTORED`.

## 12. Post-Rollback Validation
After applying restoration:
- The resulting tool baselines are re-exported and checked against Phase 14 integrity rules.
- The state fingerprint is re-computed and verified against `checkpoint.state_fingerprint`.

## 13. Failure Handling
If restoration fails or post-rollback validation fails:
- The system automatically reverts to `previous_state_fingerprint`.
- Returns `RollbackResult(restored=False, decision=SecurityDecision.DENY, ...)`
- Logs `ROLLBACK_FAILED`.
- The system **never** reports `restored=True` unless post-restoration validation succeeds.

## 14. Audit Events
All checkpoint and rollback activities emit tamper-evident audit events via `AuditLogger`:
- `CHECKPOINT_CREATED`
- `CHECKPOINT_VALIDATED`
- `CHECKPOINT_INVALID`
- `ROLLBACK_REQUESTED`
- `ROLLBACK_ALLOWED`
- `ROLLBACK_BLOCKED`
- `ROLLBACK_FAILED`
- `ROLLBACK_COMPLETED`

## 15. Phase 14 Integration
Phase 15 integrates directly with Phase 14's `ToolGovernanceRegistry`:
- `ToolGovernanceRegistry.export_baselines()` provides baseline snapshots for checkpoint creation.
- `ToolGovernanceRegistry.restore_baselines()` applies restored baselines upon approved rollback.
- Restored baselines are immediately active for Phase 14 drift detection (`validate_tool_change()`).

## 16. Security Invariants
1. Checkpoint fingerprints are deterministic.
2. Equivalent security states produce equivalent fingerprints.
3. Modified checkpoint state fails integrity validation.
4. Checkpoint integrity does not imply trust.
5. Checkpoint creation is auditable.
6. Checkpoint state is immutable.
7. Unauthorized rollback is denied.
8. Missing identity fails closed.
9. Cross-tenant rollback is denied.
10. Missing checkpoint is denied.
11. Corrupted checkpoint is denied.
12. Rollback does not automatically happen because a change was detected.
13. Rollback does not execute tools.
14. Rollback does not execute external network requests.
15. Previous state is captured before restoration.
16. Successful rollback requires post-restore validation.
17. Failed rollback must not report success.
18. Rejected rollback does not modify the current state.
19. Restored tool baselines preserve their original security semantics.
20. Checkpoint provenance does not automatically grant trust.
21. Checkpoint selection is explicit.
22. Rollback decisions are auditable.
23. Sensitive data is not stored inside checkpoints.
24. Security state after rollback must pass existing integrity validation.

## 17. Limitations
- Operates on AgentShield local configuration state; external server state must be managed via SecureMCP.
- In-memory local checkpoint history; persistent external storage backends can be connected to `CheckpointManager`.

## 18. Future Work
- Multi-node checkpoint synchronization for distributed AgentShield clusters.
- Automated security health metrics tracking across historic checkpoints.
