"""
Unit tests for policy engine and YAML parser.
"""

from agentshield.policies.engine import PolicyEngine
from agentshield.policies.rules import ToolConstraint

def test_tool_constraint_rule():
    tc = ToolConstraint(
        allowed_tools=["search_web", "read_file"],
        blocked_tools=["exec_bash"]
    )

    assert tc.is_tool_allowed("search_web")
    assert not tc.is_tool_allowed("exec_bash")
    assert not tc.is_tool_allowed("unknown_tool")

def test_policy_engine_evaluation():
    engine = PolicyEngine(policy_data={
        "tool_constraints": {
            "allowed_tools": ["read_file"],
            "blocked_tools": ["exec_bash"],
            "tool_arguments": {
                "read_file": {
                    "forbidden_paths": ["/etc/passwd"]
                }
            }
        }
    })

    # Test allowed tool
    res_ok = engine.evaluate_tool_execution("read_file", {"path": "notes.txt"})
    assert res_ok["allowed"]

    # Test forbidden path
    res_path = engine.evaluate_tool_execution("read_file", {"path": "/etc/passwd"})
    assert not res_path["allowed"]

    # Test blocked tool
    res_blocked = engine.evaluate_tool_execution("exec_bash", {"cmd": "ls"})
    assert not res_blocked["allowed"]
