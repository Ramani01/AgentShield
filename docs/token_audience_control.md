# Token / Data Audience Control Specification

## 1. Purpose & Core Security Invariant

The **Token / Data Audience Control Engine** (`AudienceValidator`, `AudienceClaim`, `AudiencePolicy`, `SecurityTokenContext`) in AgentShield enforces data disclosure controls ensuring information is only disclosed to authorized target audiences.

The core security invariant for AgentShield Token / Data Audience Control is:
> **AUTHORIZED ACCESS TO DATA DOES NOT AUTOMATICALLY MEAN AUTHORIZATION TO DISCLOSE THAT DATA TO EVERY AUDIENCE.**

> [!IMPORTANT]
> **Phase 13 provides a local security model for audience authorization. It does NOT implement real authentication, OAuth, JWT issuance, token transport, or external identity-provider integration.**

---

## 2. Core Concepts & Decoupled Dimensions

AgentShield explicitly distinguishes five orthogonal security dimensions:

- **IDENTITY**: Who is requesting access? (`UserIdentity`)
- **AUTHORIZATION**: What is the requester allowed to access? (`PolicyEngine` / RBAC)
- **AUDIENCE**: Who is this data intended/permitted to be disclosed to? (`AudienceClaim`)
- **DESTINATION**: Where is the data going? (`DestinationCategory`)
- **EGRESS**: May the data cross the security boundary? (`EgressValidator`)

### Key Decouplings:
- $\text{IDENTITY} \neq \text{AUDIENCE}$
- $\text{AUTHORIZATION} \neq \text{AUDIENCE}$
- $\text{TRUST} \neq \text{AUDIENCE}$ ($\text{TRUSTED} \neq \text{PUBLIC}$)
- $\text{PROVENANCE} \neq \text{AUDIENCE}$
- $\text{AUDIENCE} \neq \text{DESTINATION}$

---

## 3. Audience Types & Token Context Model

### Audience Types:
- `SAME_USER`: Disclosable strictly to the requesting principal.
- `SAME_TENANT`: Disclosable to any principal within the same tenant.
- `INTERNAL`: Disclosable to verified internal system components.
- `SPECIFIC_PRINCIPAL`: Disclosable strictly to an explicit principal ID.
- `APPROVED_SERVICE`: Disclosable to an approved internal service.
- `APPROVED_EXTERNAL`: Disclosable to approved external partners.
- `PUBLIC`: Explicitly disclosable publicly (requires policy authorization).
- `UNKNOWN`: Unspecified audience (fails closed to `SecurityDecision.REVIEW` / `DENY`).

### Local Token Context Representation:
```python
class SecurityTokenContext(BaseModel):
    token_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    subject_id: str
    tenant_id: str
    audience: AudienceType = AudienceType.SAME_USER
    scopes: List[str] = Field(default_factory=list)
    issued_at: float = Field(default_factory=time.time)
    expires_at: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
```

---

## 4. Security Invariants (20 Invariants Enforced)

- **INVARIANT 1**: Audience is independent from identity.
- **INVARIANT 2**: Audience is independent from trust.
- **INVARIANT 3**: Audience is independent from provenance.
- **INVARIANT 4**: Audience is independent from destination.
- **INVARIANT 5**: Authorization does not automatically authorize disclosure.
- **INVARIANT 6**: Trusted data is not automatically public.
- **INVARIANT 7**: Valid provenance does not authorize disclosure.
- **INVARIANT 8**: Valid hash does not authorize disclosure.
- **INVARIANT 9**: Content cannot modify its own audience.
- **INVARIANT 10**: Content cannot broaden its own audience.
- **INVARIANT 11**: Cross-user audience mismatch is denied (`SecurityDecision.DENY`).
- **INVARIANT 12**: Cross-tenant audience mismatch is denied (`SecurityDecision.DENY`).
- **INVARIANT 13**: Unknown audience fails closed (`SecurityDecision.REVIEW`).
- **INVARIANT 14**: Public audience requires explicit policy authorization (`policy.allow_public = True`).
- **INVARIANT 15**: Expired token context fails closed.
- **INVARIANT 16**: Token audience mismatch is denied.
- **INVARIANT 17**: Derived data cannot automatically receive a broader audience.
- **INVARIANT 18**: Mixed-audience data uses conservative audience propagation (most restrictive audience).
- **INVARIANT 19**: Audience approval does not bypass `EgressValidator`.
- **INVARIANT 20**: Rejected audience decisions are auditable.

---

## 5. Conceptual Egress & Audience Pipeline Flow

$$\text{Data} \rightarrow \mathbf{Output\ Validation} \rightarrow \mathbf{Audience\ Validation} \rightarrow \mathbf{Destination\ Validation} \rightarrow \mathbf{Egress\ Validation} \rightarrow \text{External Boundary}$$

```python
# SecurityPipeline methods
aud_res = pipeline.validate_audience(claim, identity=user_identity, token_context=tok)
egress_res = pipeline.validate_egress(egress_req, identity=user_identity)
```

---

## 6. Audience Propagation for Mixed-Source Data

When combining multiple data items $A$ and $B$:
$$\text{Audience}(C) = \text{MostRestrictive}(\text{Audience}(A), \text{Audience}(B))$$
- Ranking: `SPECIFIC_PRINCIPAL` $>$ `SAME_USER` $>$ `SAME_TENANT` $>$ `INTERNAL` $>$ `APPROVED_SERVICE` $>$ `APPROVED_EXTERNAL` $>$ `PUBLIC`.

---

## 7. Audit Behavior

Structured audit logs record:
- `AUDIENCE_VALIDATED`
- `AUDIENCE_REVIEW`
- `AUDIENCE_BLOCKED`

Raw secrets, credentials, or sensitive data payloads are **never** logged.

---

## 8. Limitations & Disclaimer

> [!WARNING]
> **Explicit Security Disclaimer**:
> Phase 13 provides local security validation of audience claims and token contexts. It does not perform network authentication, OAuth handshake, JWT signature verification, or external identity provider integration.

---

## 9. Test Coverage

- **Suite**: `tests/unit/test_token_audience_control.py`
- **Tests Added**: 37 focused unit, security invariant, negative refutation, and integration tests.
- **Regression Status**: 273 passed, 0 failed.
