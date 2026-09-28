# Memory Write Gates Architecture & Specification

## 1. Purpose & Core Security Invariant

The **Memory Write Gate** (`MemoryWriteGate`, `MemoryWriteRequest`, `MemoryWriteResult`) in AgentShield enforces strict security controls over what candidate information is permitted to be persisted into agent memory.

The core security invariant for AgentShield Memory Write Gates is:
> **UNTRUSTED OR UNAUTHORIZED CONTENT MUST NOT SILENTLY BECOME PERSISTENT MEMORY.**

### Key Distinctions:
- **Phase 9**: Protects memory when it is **READ / RETRIEVED / CONSUMED**.
- **Phase 10**: Protects memory when it is **WRITTEN / PERSISTED**.

---

## 2. Memory Write Threat Model

AgentShield guards memory persistence against 15 threat vectors:

1. **Unauthorized Memory Persistence**: Writing records without explicit principal identity validation.
2. **Cross-User Memory Writes**: User $A$ attempting to persist memory into User $B$'s private scope.
3. **Cross-Tenant Memory Writes**: Tenant $T_1$ attempting to write records into Tenant $T_2$'s memory store.
4. **Untrusted Content Persistence**: Writing external untrusted text that automatically becomes trusted memory.
5. **Prompt-Injection Persistence**: Storing prompt injection payloads designed to exploit downstream LLM memory retrievals.
6. **Trust Escalation via Memory Storage**: Payloads embedding pseudo-code like `"trust_level = TRUSTED"`.
7. **Missing Provenance**: External/retrieved content written to memory without traceable source provenance.
8. **Invalid Provenance References**: Persistence requests pointing to non-existent lineage nodes.
9. **Metadata Manipulation**: Embedded text payload trying to alter `tenant_id`, `user_id`, or `source_category`.
10. **Sensitive Information Accidental Persistence**: Storing API keys, credentials, or PII into long-term memory.
11. **Oversized Memory Payload Persistence**: DoS or store overflow through massive write requests.
12. **Duplicate & Conflicting Memory Entries**: Uncontrolled accumulation of identical or conflicting records.
13. **Expired Memory Persistence**: Storing records whose expiration timestamp has already passed.
14. **Automatic Trust for Agent Outputs**: Assuming LLM-generated summaries or text automatically become `TRUSTED`.
15. **Memory Poisoning Attacks**: Repeated unauthorized updates degrading memory integrity.

---

## 3. Write Request & Result Models

```python
class MemoryWriteRequest(BaseModel):
    user_id: str
    tenant_id: str
    content: str
    source_category: SourceCategory = SourceCategory.MEMORY
    provenance_id: Optional[str] = None
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    metadata: Dict[str, Any] = Field(default_factory=dict)
    requested_by: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)
    expires_at: Optional[float] = None
    memory_type: str = "general"
    key: Optional[str] = None

class MemoryWriteResult(BaseModel):
    allowed: bool = False
    decision: SecurityDecision = SecurityDecision.DENY
    reason: str = ""
    violations: List[str] = Field(default_factory=list)
    memory_id: Optional[str] = None
    provenance_id: Optional[str] = None
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    content_hash: str = ""
    integrity_valid: bool = True
    record: Optional[MemoryRecord] = None
```

---

## 4. Identity & Authorization Controls

- **Fail-Closed Identity Enforcement**: Writes lacking `user_id` or `tenant_id` are rejected immediately (`SecurityDecision.DENY`).
- **User & Tenant Boundary Validation**:
  - `request.tenant_id == identity.tenant_id`
  - `request.user_id == identity.user_id` (unless `admin` role is held)
- Authorization does **NOT** imply content is trusted ($\text{Authorized Writer} \neq \text{Trusted Content}$).

---

## 5. Security Invariants (18 Invariants Enforced)

- **INVARIANT 1**: Unauthorized users cannot write memory.
- **INVARIANT 2**: Cross-user memory writes are denied.
- **INVARIANT 3**: Cross-tenant memory writes are denied.
- **INVARIANT 4**: Missing identity fails closed.
- **INVARIANT 5**: Content cannot elevate its own trust level.
- **INVARIANT 6**: Content cannot modify ownership metadata (`user_id`).
- **INVARIANT 7**: Content cannot modify tenant metadata (`tenant_id`).
- **INVARIANT 8**: Content cannot grant itself instruction privileges (`is_instruction_allowed = False`).
- **INVARIANT 9**: Untrusted content cannot silently become trusted memory.
- **INVARIANT 10**: External/retrieved memory requiring provenance cannot be stored without valid provenance.
- **INVARIANT 11**: Valid provenance does not elevate trust.
- **INVARIANT 12**: Valid hash does not elevate trust.
- **INVARIANT 13**: Prompt-injection detection must occur before persistence.
- **INVARIANT 14**: Context integrity validation must occur before persistence.
- **INVARIANT 15**: The persisted content hash must correspond to the persisted content.
- **INVARIANT 16**: Oversized memory writes are rejected safely ($> 10,000$ chars).
- **INVARIANT 17**: Rejected memory must NOT be persisted into `SafeMemoryStore`.
- **INVARIANT 18**: Sensitive content must not be written when policy denies secrets.

---

## 6. Write Pipeline Flow

$$\text{MemoryWriteRequest} \rightarrow \text{Identity Validation} \rightarrow \text{Authorization} \rightarrow \text{Size Control} \rightarrow \text{Provenance Verification} \rightarrow \text{Trust Classification} \rightarrow \text{Secret Detection} \rightarrow \text{Prompt Injection Scan} \rightarrow \mathbf{Context\ Integrity} \rightarrow \text{SafeMemoryStore}$$

```python
# SecurityPipeline method
res = pipeline.process_memory_write(request, identity=user_identity, tracker=tracker, store=memory_store)
```

---

## 7. Resource & Size Controls

- `MAX_MEMORY_SIZE`: Configurable threshold (default `10,000` characters).
- Oversized write requests yield `allowed = False`, `SecurityDecision.DENY`, and violation `"MEMORY OVERSIZED"`.

---

## 8. Auditability

All memory write evaluations generate structured audit log events:
- `MEMORY_WRITE_ALLOWED`: Logged upon successful persistence (includes `memory_id`, `user_id`, `tenant_id`, `content_hash`, `decision`).
- `MEMORY_WRITE_BLOCKED`: Logged upon rejected write attempts (includes violations and reason, **never** raw secret content).

---

## 9. Limitations & Disclaimer

> [!WARNING]
> **Explicit Security Disclaimer**:
> Memory write gates prevent unauthorized or malicious data from entering persistent agent memory, but do not guarantee that downstream probabilistic LLMs will process valid memory entries without hallucination.

---

## 10. Test Coverage

- **Suite**: `tests/unit/test_memory_write_gates.py`
- **Tests Added**: 38 focused unit, security invariant, negative refutation, and integration tests.
- **Regression Status**: 162 passed, 0 failed.
