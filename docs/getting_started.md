# AgentShield Getting Started Guide

## Installation

Install AgentShield in editable mode or from source:

```bash
pip install -e .
```

## Basic Usage

To guard an agent execution function:

```python
from agentshield import AgentShield, ShieldConfig

config = ShieldConfig(
    enable_injection_detection=True,
    enable_pii_sanitization=True,
    strict_policy_mode=True
)

shield = AgentShield(config=config)

@shield.guard
def my_agent(prompt: str) -> str:
    # Call your LLM here
    return f"Response for prompt: {prompt}"

# Safe execution
result = my_agent("Explain quantum computing in simple terms.")
print(result.output)
```

## Shielding Tools & Actions

To guard agent tool execution:

```python
from agentshield import shield_tool

@shield_tool(tool_name="read_file")
def read_user_file(file_path: str) -> str:
    with open(file_path, "r") as f:
        return f.read()
```
