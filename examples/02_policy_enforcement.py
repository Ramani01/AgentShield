"""
Example 02: Policy Enforcement and Tool Call Constraints.
"""

from agentshield import shield_tool, PolicyViolationError

@shield_tool(tool_name="read_file")
def safe_read_file(file_path: str) -> str:
    return f"Contents of {file_path}"

@shield_tool(tool_name="exec_bash")
def dangerous_bash(cmd: str) -> str:
    return f"Executed {cmd}"

def main():
    print("=== AgentShield Policy Enforcement Example ===")

    # Test 1: Allowed tool with safe argument
    print("\n[Tool Call 1: safe_read_file('doc.txt')]")
    try:
        content = safe_read_file(file_path="doc.txt")
        print("Success:", content)
    except PolicyViolationError as e:
        print("Blocked:", e)

    # Test 2: Allowed tool with forbidden path
    print("\n[Tool Call 2: safe_read_file('/etc/passwd')]")
    try:
        content = safe_read_file(file_path="/etc/passwd")
        print("Success:", content)
    except PolicyViolationError as e:
        print("Blocked by Policy:", e)

    # Test 3: Blocked tool execution
    print("\n[Tool Call 3: dangerous_bash('ls')]")
    try:
        content = dangerous_bash(cmd="ls")
        print("Success:", content)
    except PolicyViolationError as e:
        print("Blocked by Policy:", e)

if __name__ == "__main__":
    main()
