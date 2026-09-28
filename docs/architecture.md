# AgentShield Architecture & System Design

## Architecture Overview

AgentShield provides defense-in-depth security, safety, and governance for autonomous AI agents and LLM applications.

```
+-----------------------------------------------------------------------+
|                             USER PROMPT                               |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                          SECURITY PIPELINE                            |
|  - Prompt Injection Scanner   - Secret Detector (API Keys)            |
|  - Jailbreak Analyzer         - PII Sanitizer                         |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                    CONTEXT & BOUNDARY ISOLATION                       |
|  - Delimiter Escaping         - Privilege Isolation                   |
|  - Token Budget Manager                                               |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                       POLICY ENGINE & RULES                           |
|  - Tool Call Constraints      - YAML Policy Enforcement               |
|  - Rate Limits & Whitelists                                           |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                     RAG & MEMORY GUARDRAILS                           |
|  - Poison Document Filter     - Document Level RBAC                   |
|  - Safe Memory Store          - Tamper Checksum Verification          |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                   PROVENANCE & AUDIT LOGGING                          |
|  - Append-Only Hash Chain     - Action Lineage Graph                  |
|  - Execution Telemetry                                                |
+-----------------------------------------------------------------------+
```

## Subsystem Breakdown

1. **`agentshield.security`**: Threat detection and input/output sanitization.
2. **`agentshield.context`**: Boundary tagging, privilege checks, token budget limits.
3. **`agentshield.memory`**: Tenant-isolated key-value memory store with SHA-256 tamper signatures.
4. **`agentshield.retrieval`**: RAG guardrails, vector retrieval access control, poison document inspection.
5. **`agentshield.policies`**: Rule engine evaluating requested tools and parameters against YAML configurations.
6. **`agentshield.provenance`**: Cryptographic audit logging and execution lineage graph tracing.
7. **`agentshield.evaluation`**: Automated red-teaming benchmarks and resilience scoring.
8. **`agentshield.api`**: FastAPI microservice server and Python client SDK.
