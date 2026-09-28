"""
AgentShield configuration definitions.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class ShieldConfig:
    """Configuration class for AgentShield."""
    enable_injection_detection: bool = True
    enable_jailbreak_detection: bool = True
    enable_pii_sanitization: bool = True
    enable_secret_detection: bool = True
    enable_vulnerability_scanning: bool = True
    enable_context_isolation: bool = True
    enable_memory_filtering: bool = True
    enable_rag_inspection: bool = True
    enable_audit_logging: bool = True
    strict_policy_mode: bool = True
    injection_threshold: float = 0.70
    jailbreak_threshold: float = 0.75
    max_token_budget: int = 4096
    audit_log_path: str = "audit_logs/agentshield_audit.jsonl"
    policy_file_path: Optional[str] = None
    custom_rules: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration options to dictionary format."""
        return {
            "enable_injection_detection": self.enable_injection_detection,
            "enable_jailbreak_detection": self.enable_jailbreak_detection,
            "enable_pii_sanitization": self.enable_pii_sanitization,
            "enable_secret_detection": self.enable_secret_detection,
            "enable_vulnerability_scanning": self.enable_vulnerability_scanning,
            "enable_context_isolation": self.enable_context_isolation,
            "enable_memory_filtering": self.enable_memory_filtering,
            "enable_rag_inspection": self.enable_rag_inspection,
            "enable_audit_logging": self.enable_audit_logging,
            "strict_policy_mode": self.strict_policy_mode,
            "injection_threshold": self.injection_threshold,
            "jailbreak_threshold": self.jailbreak_threshold,
            "max_token_budget": self.max_token_budget,
            "audit_log_path": self.audit_log_path,
            "policy_file_path": self.policy_file_path,
        }
