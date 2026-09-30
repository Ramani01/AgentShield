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
from agentshield.capabilities import CapabilityEngine
from agentshield.communication import CommunicationPolicyEngine
from agentshield.integrity import RuntimeIntegrityEngine
from agentshield.behavior import BehaviorEngine
from agentshield.containment import ContainmentManager
from agentshield.graph import SecurityGraphEngine
from agentshield.evaluation import ContainmentEvaluationEngine
from agentshield.simulation import SimulationExecutor
from agentshield.benchmark import BenchmarkRunner

__version__ = "0.2.2"

class AgentShield:
    """Convenience facade for AgentShield security initialization."""

    def __init__(self, config: ShieldConfig = None):
        self.config = config or ShieldConfig()
        self.pipeline = SecurityPipeline(config=self.config)
        self.agent_wrapper = ShieldedAgent(config=self.config)
        self.policy_engine = PolicyEngine(policy_file_path=self.config.policy_file_path)
        self.capability_engine = CapabilityEngine(audit_logger=self.pipeline.audit_logger)
        self.communication_engine = CommunicationPolicyEngine(
            audit_logger=self.pipeline.audit_logger,
            capability_engine=self.capability_engine
        )
        self.integrity_engine = RuntimeIntegrityEngine(
            audit_logger=self.pipeline.audit_logger,
            capability_engine=self.capability_engine,
            comm_engine=self.communication_engine
        )
        self.behavior_engine = BehaviorEngine(
            audit_logger=self.pipeline.audit_logger,
            capability_engine=self.capability_engine,
            comm_engine=self.communication_engine,
            integrity_engine=self.integrity_engine
        )
        self.containment_manager = ContainmentManager(
            audit_logger=self.pipeline.audit_logger,
            capability_engine=self.capability_engine,
            comm_engine=self.communication_engine,
            integrity_engine=self.integrity_engine
        )
        self.graph_engine = SecurityGraphEngine(
            audit_logger=self.pipeline.audit_logger
        )
        self.evaluation_engine = ContainmentEvaluationEngine(
            audit_logger=self.pipeline.audit_logger,
            capability_engine=self.capability_engine,
            comm_engine=self.communication_engine,
            integrity_engine=self.integrity_engine,
            behavior_engine=self.behavior_engine,
            containment_manager=self.containment_manager,
            graph_engine=self.graph_engine
        )
        self.simulation_executor = SimulationExecutor(shield=self)
        self.benchmark_runner = BenchmarkRunner(shield=self)
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

