# AgentShield Security Policy Guide

AgentShield uses declarative YAML or JSON security policies to govern agent tool calls and data access.

## Example Policy (`policy.yaml`)

```yaml
version: "1.0"
policy_name: "enterprise_agent_policy"

tool_constraints:
  allowed_tools:
    - "search_web"
    - "read_file"
    - "calculate"
  blocked_tools:
    - "exec_bash"
    - "drop_database"
  tool_arguments:
    read_file:
      forbidden_paths:
        - "/etc/passwd"
        - "*.env"

pii_rules:
  mask_emails: true
  mask_ssn: true

rate_limits:
  max_requests_per_minute: 60
  max_tool_calls_per_execution: 10
```

## Loading Custom Policies

Pass the custom policy path to `ShieldConfig`:

```python
from agentshield import ShieldConfig, AgentShield

config = ShieldConfig(policy_file_path="configs/default_policy.yaml")
shield = AgentShield(config=config)
```
