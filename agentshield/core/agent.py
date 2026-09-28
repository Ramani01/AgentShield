"""
ShieldedAgent Wrapper & Decorators Module.
"""

from functools import wraps
from typing import Callable, Any, Dict, Optional
from dataclasses import dataclass

from agentshield.core.config import ShieldConfig
from agentshield.core.pipeline import SecurityPipeline
from agentshield.provenance.lineage import ActionLineage

@dataclass
class ShieldedResult:
    output: Any
    metadata: Dict[str, Any]
    trace_id: str

class ShieldedAgent:
    """Wrapper around arbitrary agent execution functions to provide enterprise defense."""

    def __init__(self, config: Optional[ShieldConfig] = None):
        self.config = config or ShieldConfig()
        self.pipeline = SecurityPipeline(config=self.config)

    def guard(self, fn: Callable[..., Any]) -> Callable[..., ShieldedResult]:
        """Decorator to wrap an agent execution function with AgentShield security."""
        @wraps(fn)
        def wrapper(*args, **kwargs) -> ShieldedResult:
            lineage = ActionLineage()
            
            # Identify prompt input
            input_prompt = ""
            if args:
                input_prompt = str(args[0])
            elif "prompt" in kwargs:
                input_prompt = str(kwargs["prompt"])
            elif "user_input" in kwargs:
                input_prompt = str(kwargs["user_input"])

            # 1. Pre-execution security checks
            sanitized_input, meta = self.pipeline.inspect_input(input_prompt)

            # Record input lineage node
            input_node = lineage.record_step("USER_PROMPT", fn.__name__, input_prompt)

            # Update args/kwargs with sanitized input if string passed
            if args and isinstance(args[0], str):
                args = (sanitized_input,) + args[1:]
            elif "prompt" in kwargs:
                kwargs["prompt"] = sanitized_input

            # 2. Execute target function
            raw_output = fn(*args, **kwargs)

            # 3. Post-execution security checks
            output_str = str(raw_output)
            safe_output = self.pipeline.inspect_output(output_str)

            # Record output lineage node
            lineage.record_step("AGENT_OUTPUT", fn.__name__, safe_output, parent_id=input_node)

            result_meta = {
                "input_inspection": meta,
                "lineage_trace": lineage.get_lineage_trace()
            }

            return ShieldedResult(
                output=safe_output,
                metadata=result_meta,
                trace_id=lineage.trace_id
            )

        return wrapper
