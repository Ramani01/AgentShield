# AgentShield API Reference

## Top-Level Exports (`agentshield`)

- **`AgentShield(config: Optional[ShieldConfig])`**: Main facade for initializing pipeline and agent guards.
- **`ShieldConfig(...)`**: Configuration object for scanners, policies, log paths, and thresholds.
- **`ShieldedAgent(config: Optional[ShieldConfig])`**: Agent decorator class providing `@guard`.
- **`shield_tool(tool_name: Optional[str])`**: Decorator for tool level policy & security checks.

## Security Scanners (`agentshield.security`)

- **`PromptInjectionScanner(threshold: float)`**: Detects direct & indirect prompt injection attempts.
- **`JailbreakDetector(threshold: float)`**: Detects DAN, roleplay, and cipher jailbreaks.
- **`InputOutputSanitizer(mask_pii: bool)`**: Redacts PII and sanitizes script/HTML content.
- **`SecretDetector()`**: Scans for leaked credentials (API keys, RSA keys, JWTs).
- **`VulnerabilityScanner()`**: Detects dangerous OS shell commands and path traversal attempts.

## Provenance & Audit (`agentshield.provenance`)

- **`AuditLogger(log_file_path: str)`**: Append-only SHA-256 hash chained log system.
- **`ActionLineage(trace_id: str)`**: Graph tracing of user inputs, agent decisions, and tool calls.
- **`ExecutionTelemetry()`**: Tracks threat detection metrics.
