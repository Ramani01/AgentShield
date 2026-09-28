"""
Tool & Action Vulnerability Scanner Module.
"""

import re
from typing import Dict, Any, List

class VulnerabilityScanner:
    """Scans agent tool calls and generated commands for dangerous operations."""

    HIGH_RISK_COMMANDS = [
        (r"(?i)\brm\s+-rf\b", "Dangerous File Deletion (rm -rf)"),
        (r"(?i)\bformat\s+[a-z]:", "Drive Formatting Command"),
        (r"(?i)\bchmod\s+777\b", "Unsafe File Permissions (chmod 777)"),
        (r"(?i)\bdrop\s+database\b", "SQL Drop Database"),
        (r"(?i)\bdrop\s+table\b", "SQL Drop Table"),
        (r"(?i)\beval\s*\(", "Arbitrary Code Evaluation (eval)"),
        (r"(?i)\bexec\s*\(", "Arbitrary Code Execution (exec)"),
        (r"(?i)\bsubprocess\.(Popen|call|run)\b", "Direct Subprocess Invocation"),
        (r"(?i)\bcurl\s+.*\|\s*sh\b", "Remote Script Execution Pipe"),
    ]

    PATH_TRAVERSAL_PATTERN = r"(\.\./|\.\.\\)"

    def scan_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scans tool execution parameters for shell injection, path traversal, or database drops.
        """
        threats = []

        # Check arguments converted to string
        arg_str = str(arguments)

        for pattern, risk in self.HIGH_RISK_COMMANDS:
            if re.search(pattern, arg_str):
                threats.append({
                    "risk_type": risk,
                    "pattern": pattern,
                    "severity": "CRITICAL"
                })

        # Path traversal check
        if re.search(self.PATH_TRAVERSAL_PATTERN, arg_str):
            threats.append({
                "risk_type": "Path Traversal Attempt",
                "pattern": self.PATH_TRAVERSAL_PATTERN,
                "severity": "HIGH"
            })

        return {
            "is_vulnerable": len(threats) > 0,
            "threats": threats,
            "tool_name": tool_name
        }
