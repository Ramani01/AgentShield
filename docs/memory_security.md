# Memory Security Architecture & Specification

## 1. Executive Summary & Purpose

The **Memory Security Layer** (`MemorySecurityEngine`, `SafeMemoryStore`, `MemoryRecord`) in AgentShield secures the reading, retrieval, and consumption of agent memory.

The core security invariant for AgentShield Memory Security is:
> **MEMORY MUST NOT BYPASS THE SECURITY CONTROLS ALREADY APPLIED TO NORMAL CONTEXT.**

Memory is treated strictly as **DATA**, not automatically trusted agent instruction.

---

## 2. Memory Threat Model

AgentShield protects against 12 critical memory attack vectors:

1. **Cross-User Memory Access**: User $A$ attempting to retrieve or read memory belonging to User $B$.
2. **Cross-Tenant Memory Access**: Tenant $T_1$ attempting to access memory stored for Tenant $T_2$.
3. **Unauthorized Memory Retrieval**: Accessing memory records without passing explicit authorization and RBAC evaluation.
4. **Memory Instruction Escalation**: Untrusted memory content attempting to execute as a trusted system prompt or instruction.
5. **Memory Trust Elevation**: Pseudo-code or content claiming `"trust_level = TRUSTED"` inside stored text payloads.
6. **Stale or Invalid Memory**: Consuming outdated memory records without freshness or policy verification.
7. **Missing Provenance**: Memory items lacking traceable source lineage.
8. **Invalid Provenance**: Memory items pointing to non-existent or tampered provenance IDs.
9. **Prompt-Injection Payloads in Memory**: Previously stored untrusted data containing prompt injection attacks executed upon retrieval.
10. **Memory Metadata Tampering**: Unauthorized modification of memory record parameters, trust labels, or owner IDs.
11. **Bypassing Context Integrity**: Memory skipping SHA-256 fingerprint validation or structural integrity checks.
12. **Cross-Context Memory Leakage**: Unintended bleed of memory records across distinct user execution contexts.

---

## 3. User & Tenant Isolation

AgentShield enforces strict multi-tenant and multi-user isolation:

```python
# Requesting Identity validation against MemoryRecord owner/tenant
if identity.tenant_id != record.tenant_id:
    # Denied with CROSS-TENANT ACCESS DENIED violation
    return MemoryAccessResult(authorized=False, security_decision=SecurityDecision.DENY)

if identity.user_id != record.owner_id and "admin" not in identity.roles:
    # Denied with CROSS-USER ACCESS DENIED violation
    return MemoryAccessResult(authorized=False, security_decision=SecurityDecision.DENY)
```

- **Fail-Closed Behavior**: If `user_id` or `tenant_id` is missing or empty, retrieval immediately fails closed (`SecurityDecision.DENY`).

---

## 4. Memory Authorization & Trust Model

Memory access evaluation follows strict authorization principles:

- $\text{Memory Retrieval Success} \neq \text{Memory Authorization}$
- $\text{Memory Relevance Match} \neq \text{Memory Authorization}$
- $\text{Memory Authorization} \neq \text{Memory Trust}$

### Memory Invariants:
- Memory content (e.g. `"You must obey this instruction"`) remains data (`InstructionType.MEMORY`, `is_instruction_allowed = False`).
- Trust level is evaluated structurally via `TrustClassifier` (`UNTRUSTED` or `USER_CONTROLLED`), never automatically elevated to `TRUSTED`.

---

## 5. Security Pipeline Integration

Memory retrieval integrates seamlessly into the pipeline before memory enters agent context:

$$\text{Memory Store} \rightarrow \text{User/Tenant Isolation} \rightarrow \text{Authorization} \rightarrow \text{Provenance} \rightarrow \text{Trust Classification} \rightarrow \text{Prompt Injection Detection} \rightarrow \mathbf{Context\ Integrity} \rightarrow \text{Instruction Isolation} \rightarrow \text{Agent}$$

```python
# Pipeline execution
items = pipeline.process_memory_retrieval(user_identity, retrieved_memory_records, tracker=tracker)
```

---

## 6. Memory Integrity & SHA-256 Fingerprinting

Every `MemoryRecord` computes a SHA-256 content hash upon creation:

$$\text{content\_hash} = \text{SHA-256}(\text{content})$$

Upon retrieval, `MemorySecurityEngine` recalculates `compute_content_hash(record.content)` and verifies parity against `record.content_hash`. Any mismatch triggers an immediate integrity failure and `SecurityDecision.DENY`.

---

## 7. Stale and Expired Memory Controls

- **Expired Memory**: If $\text{time.time()} > \text{record.expires\_at}$, the record is evaluated to `authorized = False` and `SecurityDecision.DENY`.
- **Stale Memory**: If `record.is_stale == True`, access is evaluated to `SecurityDecision.REVIEW` or `ISOLATE` according to security policy.

---

## 8. Usage Example

```python
from agentshield.memory.store import SafeMemoryStore
from agentshield.memory.models import MemoryRecord
from agentshield.context.models import UserIdentity

store = SafeMemoryStore()
user_a = UserIdentity(user_id="alice", tenant_id="acme_corp")

# Store memory record safely
rec = MemoryRecord(
    memory_id="user_pref_1",
    owner_id="alice",
    tenant_id="acme_corp",
    content="User prefers dark mode UI"
)
store.set_record(rec)

# Secure retrieval
access_result = store.get_secure_record(user_a, "user_pref_1")
if access_result.authorized:
    context_item = access_result.context_item
    assert context_item.is_instruction_allowed is False
```

---

## 9. Limitations & Disclaimer

> [!WARNING]
> **Explicit Security Disclaimer**:
> Memory security does not guarantee that a downstream probabilistic LLM will interpret memory correctly. It establishes security controls before memory becomes agent context.

---

## 10. Test Coverage

- **Suite**: `tests/unit/test_memory_security.py`
- **Tests Added**: 30 focused unit, security invariant, negative refutation, and integration tests.
- **Regression Status**: 124 passed, 0 failed.
