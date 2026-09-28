# AgentShield Phase 19 — API & Framework Integration

## 1. Overview

Phase 19 turns AgentShield into a clean, reusable integration framework that can be embedded into AI agent applications, especially FastAPI / Python services.

It connects the application execution lifecycle to all 13 underlying AgentShield security controls without inventing new security logic or bypassing existing security invariants.

---

## 2. Integration Architecture

```
HTTP Request / Application Call
       │
       ▼
[ AgentShieldMiddleware / FastAPI Scope ]
       │
       ▼ (Extracts UserIdentity & Tenant Context)
[ AgentShieldAdapter ]
       │
       ├── Pre-Execution: Input Inspection & Prompt Injection Scanner
       ├── Pre-Execution: Trust Labeling & Context Integrity Engine
       ├── Pre-Execution: Instruction Boundary Isolation
       ├── Execution Gate: Memory Security & Memory Write Gate
       ├── Execution Gate: Egress Control & Audience Control
       ├── Governance: Tool Governance Registry & Change Detection
       ├── Evaluation: Security Evaluation Engine & Checkpoints
       └── Telemetry: Tamper-Evident SHA-256 Audit Logger
       │
       ▼
[ Application Handler / AI Agent Core ]
       │
       ▼ (Output & Action Validation + Secret/PII Redaction)
HTTP Response / Result Payload
```

---

## 3. Public Integration API (`agentshield.integration`)

The integration layer provides a clean, Pydantic-based public API:

- **`AgentShieldAdapter`**: Primary facade for application-level security calls.
- **`AgentShieldMiddleware`**: ASGI middleware for HTTP identity extraction, fail-closed enforcement, request inspection, and output secret redaction.
- **`ShieldRequest`**: Request payload containing prompt, identity, context items, and metadata.
- **`ShieldOutputRequest`**: Agent output payload for validation and redaction.
- **`ShieldActionRequest`**: Proposed tool or system action payload.
- **`ShieldIdentity`**: Context object containing `user_id`, `tenant_id`, `roles`, and `trust_level`.
- **`ShieldResponse`**: Structured decision response (`decision`, `allowed`, `sanitized_content`, `reason`, `violations`).

---

## 4. Security Decisions

Security decisions returned by `AgentShieldAdapter` are explicit:

| Decision | Meaning | Behavior |
| :--- | :--- | :--- |
| **`ALLOW`** | Request or output passed all security controls. | Execution proceeds with `sanitized_content`. |
| **`DENY`** | Violation detected (prompt injection, secret leak, policy violation, cross-tenant attempt). | Request short-circuited or blocked with `allowed=False`. |
| **`REVIEW`** | Suspicious tool drift or output anomaly requiring review. | Action held for administrative approval. |
| **`ISOLATE`** | Untrusted or boundary-violating context detected. | Context quarantined in isolated instruction boundary. |

---

## 5. FastAPI Integration Example

Integrating AgentShield into a FastAPI application:

```python
from fastapi import FastAPI, Depends
from agentshield import AgentShield, ShieldConfig
from agentshield.integration import (
    AgentShieldMiddleware,
    ShieldIdentity,
    get_security_context,
    guard_fastapi_endpoint
)

app = FastAPI(title="My Secure AI Agent App")

# Initialize AgentShield
shield = AgentShield(config=ShieldConfig(strict_policy_mode=True))

# Attach AgentShield middleware for automatic identity propagation & inspection
app.add_middleware(
    AgentShieldMiddleware,
    adapter=shield.adapter,
    enforce_identity=True,
    tenant_header="x-tenant-id",
    user_header="x-user-id"
)

@app.post("/agent/chat")
@guard_fastapi_endpoint(adapter=shield.adapter)
def chat_endpoint(
    request_data: dict,
    identity: ShieldIdentity = Depends(get_security_context)
):
    # Safe handler execution; prompt was inspected and context propagated
    return {"reply": f"Hello {identity.user_id} from {identity.tenant_id}!"}
```

---

## 6. Security Invariants Preserved

1. **Fail-Closed Enforcement**: Missing required identity or tenant context triggers an immediate `DENY` decision.
2. **No Secret Leakage**: Credentials (AWS keys, GitHub tokens, JWTs, RSA keys) are redacted from outputs before leaving the boundary.
3. **Tenant Isolation**: Cross-tenant memory access and state manipulation are strictly prohibited.
4. **Read-Only Dashboard**: The security dashboard remains read-only for visualization and observability.
5. **Framework Independence**: Core security logic in `SecurityPipeline` remains framework-independent and pure Python.

---

## 7. Local Startup & Testing

To run the complete Phase 19 test suite:

```bash
python -m pytest tests/unit/test_integration.py
```
