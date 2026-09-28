"""
AgentShield: Security, Safety, and Governance Framework for Autonomous AI Agents.
"""

from agentshield.core.config import ShieldConfig
from agentshield.core.agent import ShieldedAgent, ShieldedResult
from agentshield.core.pipeline import SecurityPipeline
from agentshield.core.interceptor import shield_tool, ToolInterceptor
from agentshield.core.exceptions import (
    AgentShieldError,
    SecurityViolationError,
    PolicyViolationError,
    SanitizationError,
    ContextBoundaryError,
    MemorySecurityError,
    RetrievalSecurityError
)
from agentshield.security.injection import PromptInjectionScanner, PromptInjectionDetector
from agentshield.security.models import RiskLevel, InjectionCategory, PromptInjectionResult
from agentshield.security.jailbreak import JailbreakDetector
from agentshield.security.sanitizer import InputOutputSanitizer
from agentshield.security.secrets import SecretDetector
from agentshield.security.vulnerabilities import VulnerabilityScanner
from agentshield.policies.engine import PolicyEngine
from agentshield.provenance.logger import AuditLogger
from agentshield.provenance.lineage import ActionLineage, ProvenanceTracker
from agentshield.provenance.models import ProvenanceRecord, compute_content_hash
from agentshield.context.boundary import ContextBoundary, InstructionBoundary
from agentshield.context.models import (
    ContextItem,
    UserIdentity,
    InstructionType,
    SourceCategory,
    TrustLevel,
    SecurityDecision,
    TrustLabel,
    INSTRUCTION_PRIORITIES
)
from agentshield.context.trust_classifier import TrustClassifier
from agentshield.memory.store import SafeMemoryStore
from agentshield.retrieval.rag_guard import RAGGuardrail
from agentshield.integration import (
    AgentShieldAdapter,
    AgentShieldMiddleware,
    ShieldDecision,
    ShieldIdentity,
    ShieldRequest,
    ShieldOutputRequest,
    ShieldActionRequest,
    ShieldResponse
)

__version__ = "0.1.0"

class AgentShield:
    """Convenience facade for AgentShield security initialization."""

    def __init__(self, config: ShieldConfig = None):
        self.config = config or ShieldConfig()
        self.pipeline = SecurityPipeline(config=self.config)
        self.agent_wrapper = ShieldedAgent(config=self.config)
        self.policy_engine = PolicyEngine(policy_file_path=self.config.policy_file_path)
        self.adapter = AgentShieldAdapter(pipeline=self.pipeline, config=self.config)

    def guard(self, fn):
        """Wraps function with AgentShield security."""
        return self.agent_wrapper.guard(fn)

    def scan_prompt(self, text: str):
        """Scans prompt for injections and threats."""
        return self.pipeline.inspect_input(text)

__all__ = [
    "AgentShield",
    "ShieldConfig",
    "ShieldedAgent",
    "ShieldedResult",
    "SecurityPipeline",
    "shield_tool",
    "ToolInterceptor",
    "PromptInjectionScanner",
    "PromptInjectionDetector",
    "PromptInjectionResult",
    "RiskLevel",
    "InjectionCategory",
    "JailbreakDetector",
    "InputOutputSanitizer",
    "SecretDetector",
    "VulnerabilityScanner",
    "PolicyEngine",
    "AuditLogger",
    "ActionLineage",
    "ProvenanceTracker",
    "ProvenanceRecord",
    "compute_content_hash",
    "ContextBoundary",
    "InstructionBoundary",
    "TrustClassifier",
    "ContextItem",
    "UserIdentity",
    "InstructionType",
    "SourceCategory",
    "TrustLevel",
    "SecurityDecision",
    "TrustLabel",
    "INSTRUCTION_PRIORITIES",
    "SafeMemoryStore",
    "RAGGuardrail",
    "AgentShieldError",
    "SecurityViolationError",
    "PolicyViolationError",
    "SanitizationError",
    "ContextBoundaryError",
    "MemorySecurityError",
    "RetrievalSecurityError",
    "AgentShieldAdapter",
    "AgentShieldMiddleware",
    "ShieldDecision",
    "ShieldIdentity",
    "ShieldRequest",
    "ShieldOutputRequest",
    "ShieldActionRequest",
    "ShieldResponse"
]

