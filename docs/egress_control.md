# Egress Control Architecture & Specification

## 1. Purpose & Core Security Invariant

The **Egress Control Engine** (`EgressValidator`, `EgressRequest`, `EgressValidationResult`) in AgentShield enforces strict security validation before information is permitted to leave the AgentShield security boundary.

The core security invariant for AgentShield Egress Control is:
> **AUTHORIZED ACCESS TO DATA DOES NOT AUTOMATICALLY MEAN AUTHORIZATION TO EXPORT THAT DATA.**

> [!IMPORTANT]
> - **Phase 11**: Validates outputs and proposed actions.
> - **Phase 12**: Determines whether information is permitted to cross the AgentShield security boundary.
> - **Phase 12 does NOT perform external network communication.**

---

## 2. Egress Threat Model

AgentShield protects data egress against 18 threat vectors:

1. **Unauthorized Data Export**: Exfiltrating information without valid identity authorization.
2. **Cross-Tenant Data Leakage**: Tenant $T_1$ exporting data owned by Tenant $T_2$.
3. **Cross-User Data Leakage**: User $A$ exporting private data belonging to User $B$.
4. **Sensitive Data Leaving Boundary**: Transmitting unredacted secrets or credentials.
5. **Secrets Exfiltration**: Exposing API keys or certificates in egress payloads.
6. **Untrusted Data Exported to Trusted Sink**: Forwarding raw web/external data into trusted internal sinks without review.
7. **Export to Unauthorized Destinations**: Sending data to unapproved or blocked endpoints.
8. **Destination Spoofing**: Text payloads attempting `"destination = internal"` pseudo-code manipulation.
9. **Destination Policy Bypass**: Attempting to bypass endpoint policy checks.
10. **Agent Output Egress Bypass**: Agent-generated text bypassing egress controls.
11. **Loss of Provenance Lineage**: Dropping origin lineage before data leaves the boundary.
12. **Metadata Manipulation**: Embedded text payload trying to alter structural identity or tenant metadata.
13. **Oversized Data Export**: DoS or store overflow through massive export payloads.
14. **Bulk Data Export**: Uncontrolled bulk item exfiltration.
15. **High-Risk Destination Egress**: Unverified third-party external webhooks or sinks.
16. **Missing Identity**: Egress requests missing user or tenant identity.
17. **Missing Destination**: Requests without target endpoint specs.
18. **Ambiguous Destination**: Unclear destination scopes failing open.

---

## 3. Egress Request & Result Models

```python
class DestinationCategory(str, Enum):
    INTERNAL = "INTERNAL"
    SAME_TENANT = "SAME_TENANT"
    SAME_USER = "SAME_USER"
    APPROVED_EXTERNAL = "APPROVED_EXTERNAL"
    UNKNOWN_EXTERNAL = "UNKNOWN_EXTERNAL"
    BLOCKED = "BLOCKED"

class EgressRequest(BaseModel):
    egress_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    tenant_id: str
    agent_id: str = "default_agent"
    data: str
    data_type: str = "text"
    destination: str
    destination_category: DestinationCategory = DestinationCategory.UNKNOWN_EXTERNAL
    purpose: Optional[str] = None
    provenance_id: Optional[str] = None
    parent_provenance_ids: List[str] = Field(default_factory=list)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    content_hash: str = ""
    item_count: int = 1
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)

class EgressValidationResult(BaseModel):
    egress_id: Optional[str] = None
    allowed: bool = False
    decision: SecurityDecision = SecurityDecision.DENY
    reason: str = ""
    violations: List[str] = Field(default_factory=list)
    sensitive_data_detected: bool = False
    destination_allowed: bool = False
    authorization_valid: bool = True
    provenance_valid: bool = True
    integrity_valid: bool = True
    trust_valid: bool = True
    is_high_risk: bool = False
    validation_time_ms: float = 0.0
    timestamp: float = Field(default_factory=time.time)
```

---

## 4. Security Invariants (20 Invariants Enforced)

- **INVARIANT 1**: Missing required identity fails closed.
- **INVARIANT 2**: Cross-tenant data export is denied.
- **INVARIANT 3**: Cross-user private data export is denied.
- **INVARIANT 4**: Destination authorization is independent from data authorization.
- **INVARIANT 5**: Valid provenance does not authorize egress.
- **INVARIANT 6**: Valid hash does not authorize egress.
- **INVARIANT 7**: Trust does not automatically authorize egress.
- **INVARIANT 8**: Untrusted content cannot self-authorize export.
- **INVARIANT 9**: Exported data cannot modify its own destination metadata.
- **INVARIANT 10**: Exported data cannot modify its own tenant metadata.
- **INVARIANT 11**: Exported data cannot modify its own user metadata.
- **INVARIANT 12**: Blocked destinations are denied (`SecurityDecision.DENY`).
- **INVARIANT 13**: Unknown destinations fail closed unless explicitly permitted (`SecurityDecision.REVIEW`).
- **INVARIANT 14**: Sensitive data cannot leave when policy denies secrets.
- **INVARIANT 15**: Oversized export is rejected or reviewed ($> 10,000$ chars or $> 50$ items).
- **INVARIANT 16**: Integrity mismatch prevents unsafe export.
- **INVARIANT 17**: Missing required provenance fails safely.
- **INVARIANT 18**: High-risk external egress requires `SecurityDecision.REVIEW`.
- **INVARIANT 19**: Rejected egress is never passed to an external executor.
- **INVARIANT 20**: Egress decisions are auditable.

---

## 5. Conceptual Egress Pipeline Flow

$$\text{Agent / App} \rightarrow \text{Output Validation} \rightarrow \text{Egress Request} \rightarrow \text{Identity \& Scope} \rightarrow \text{Destination Policy} \rightarrow \text{Secret Detection} \rightarrow \mathbf{Egress\ Validation} \rightarrow \text{External Boundary}$$

```python
# SecurityPipeline method
res = pipeline.validate_egress(egress_request, identity=user_identity, tracker=tracker)
```

---

## 6. Audit Behavior

Structured audit logs record:
- `EGRESS_ALLOWED`
- `EGRESS_REVIEW`
- `EGRESS_BLOCKED`

Raw secrets, credentials, and full private data are **never** logged in audit trails.

---

## 7. Limitations & Disclaimer

> [!WARNING]
> **Explicit Security Disclaimer**:
> Phase 12 validates egress permission before data crosses the AgentShield boundary. It does not perform actual external network transport or guarantee external endpoint behavior.

---

## 8. Test Coverage

- **Suite**: `tests/unit/test_egress_control.py`
- **Tests Added**: 42 focused unit, security invariant, negative refutation, and integration tests.
- **Regression Status**: 236 passed, 0 failed.
