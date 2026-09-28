# AgentShield Formal Security Model

This document specifies the formal security model for the **AgentShield** governance framework. It defines the formal security decision function, invariant guarantees, trust boundary enforcement mechanics, and data classification transitions.

---

## 1. Formal Security Model Architecture

AgentShield models AI agent execution as a state transition system governed by a deterministic security pipeline function \( S \).

Let:
- \( I \in \mathcal{I} \) be the incoming user prompt or external trigger.
- \( C \in \mathcal{C} \) be the system context (system prompt, developer instructions, role definitions).
- \( R \in \mathcal{R} \) be retrieved knowledge base context (RAG documents, web scraping).
- \( M \in \mathcal{M} \) be persistent agent memory state.
- \( P \in \mathcal{P} \) be the configured security policy.
- \( T \in \mathcal{T} \) be requested tool calls or actions.
- \( O \in \mathcal{O} \) be the final agent response output.

The primary security objective of AgentShield is to ensure that for all state transitions, no untrusted input \( I_{untrusted} \) or retrieved data \( R_{untrusted} \) can alter system context \( C \), violate policy \( P \), trigger unauthorized tool execution \( T_{unauthorized} \), or exfiltrate protected assets in output \( O \).

---

## 2. Formal Security Decision Function

AgentShield evaluates every input, tool request, and output against a formal decision function \( \mathcal{D} \):

\[
\mathcal{D}(x, \text{Context}, \text{Policy}) \rightarrow \{\text{ALLOW}, \text{DENY}, \text{ISOLATE}, \text{REVIEW}\}
\]

Where:
- **`ALLOW`**: Granted iff:
  - Injection Threat Score \( < \text{Threshold}_{\text{inj}} \)
  - Jailbreak Threat Score \( < \text{Threshold}_{\text{jb}} \)
  - Tool \( T \in P_{\text{allowed\_tools}} \)
  - Tool Arguments \( A \notin P_{\text{forbidden\_patterns}} \)
  - Action Role Level \( \le \text{Current Role Level} \)
- **`DENY`**: Evaluated iff any critical policy violation or injection threat exceeds configured safety thresholds. Execution halts immediately and raises `SecurityViolationError` or `PolicyViolationError`.
- **`ISOLATE`**: Evaluated when input/output contains sanitizable elements (e.g. PII, secrets, HTML/script tags, boundary delimiter collisions). Data is rewritten before proceeding.
- **`REVIEW`**: Triggered when action risk rating or ambiguity requires Human-in-the-Loop (HITL) manual authorization.

---

## 3. Trust Level Transitions & Boundary Mechanics

All data entering the AgentShield pipeline undergoes deterministic trust level classification and boundary tagging:

```
[ USER_CONTROLLED ]  ──►  [ Context Boundary ]  ──►  ISOLATE (Escape Delimiters & Wrap)
                                                         │
                                                         ▼
[ UNTRUSTED RAG ]    ──►  [ Retrieval Guard ]   ──►  DENY if Poisoned / Role Unauthorized
                                                         │
                                                         ▼
[ AGENT PIPELINE ]   ──►  [ Policy Engine ]     ──►  DENY if Tool / Path Blocked
                                                         │
                                                         ▼
[ OUTGOING DATA ]    ──►  [ Output Sanitizer ]  ──►  ISOLATE (Redact Secrets & PII)
```

### Boundary Enforcement Rules

1. **System vs. User Delimiter Escaping (TB-01, TB-02)**:
   - System prompts are wrapped in `<|system_context|>`.
   - User inputs are wrapped in `<|user_input|>` with all occurrence of `<|system_context|>` sanitized to `&lt;|system_context|&gt;`.
2. **Retrieval Boundary Sanitation (TB-03)**:
   - All retrieved documents pass through `DocumentAccessControl` (RBAC role verification) and `PoisonDocumentFilter` (injection scanning) before injection into the prompt window.
3. **Memory Boundary Sanitation (TB-04)**:
   - Prior to persisting into `SafeMemoryStore`, write payloads pass through `MemoryFilter` to redact secrets and PII.
   - Retaining entries requires SHA-256 HMAC signature validation (`TamperDetector`).
4. **Action & Egress Sanitation (TB-05, TB-06)**:
   - Tool calls pass through `VulnerabilityScanner` and `PolicyEngine`.
   - Generated text output passes through `SecretDetector` and `InputOutputSanitizer` prior to user display.

---

## 4. Invariant Guarantees

AgentShield enforces five hard security invariants across all execution paths:

- **Invariant 1 (Non-Bypassability)**: No agent tool call or response generation can execute without passing through `SecurityPipeline`.
- **Invariant 2 (Delimiter Isolation)**: User inputs cannot inject system tags into the prompt context.
- **Invariant 3 (Audit Traceability)**: Every state transition produces an append-only JSONL log entry linked by SHA-256 hash chaining.
- **Invariant 4 (Tenant Memory Isolation)**: Memory queries for `Tenant_A` can never return state records owned by `Tenant_B`.
- **Invariant 5 (Fail Closed Safety)**: Unhandled exceptions or ambiguous policy rules default to `DENY`.

---

## 5. Current Implementation Status

Based on code audit of `agentshield/`:

### ✅ Fully Implemented
- Regex-based Prompt Injection & Jailbreak Scanning ([`injection.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/security/injection.py), [`jailbreak.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/security/jailbreak.py)).
- Secret & PII Redaction ([`secrets.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/security/secrets.py), [`sanitizer.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/security/sanitizer.py)).
- Context Delimiter Tagging & Escaping ([`boundary.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/context/boundary.py)).
- In-memory tenant isolation & HMAC/SHA-256 checksums ([`store.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/memory/store.py), [`tamper.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/memory/tamper.py)).
- Document ACL & RAG poison filter ([`rag_guard.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/retrieval/rag_guard.py)).
- Declarative YAML policy engine for tool whitelist/blacklist ([`engine.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/policies/engine.py)).
- SHA-256 hash-chained JSONL audit logger ([`logger.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/provenance/logger.py)).

### 🟡 Partially Implemented
- Vulnerability scanning for tool arguments ([`vulnerabilities.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/security/vulnerabilities.py)): String-matching regex without full AST shell/SQL parsing.
- Privilege Isolation ([`isolation.py`](file:///c:/Users/hp/Desktop/AgentShield/agentshield/context/isolation.py)): Basic role hierarchy comparison without granular policy mapping.

### ❌ Not Implemented (Planned for Future Phases)
- Human-in-the-loop (HITL) approval queue for `REVIEW` decisions.
- Semantic vector store bindings (Pinecone, ChromaDB, FAISS).
- AST syntactic analysis for dynamic tool command evaluation.
