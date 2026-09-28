"""
Context boundary, instruction isolation, trust classification, integrity validation, and privilege components.
"""

from agentshield.context.boundary import ContextBoundary, InstructionBoundary
from agentshield.context.models import (
    ContextItem,
    UserIdentity,
    InstructionType,
    SourceCategory,
    TrustLevel,
    SecurityDecision,
    TrustLabel,
    IntegrityStatus,
    ContextIntegrityResult,
    INSTRUCTION_PRIORITIES
)
from agentshield.context.trust_classifier import TrustClassifier
from agentshield.context.integrity import ContextIntegrityEngine
from agentshield.context.isolation import PrivilegeIsolator
from agentshield.context.tokens import TokenManager

__all__ = [
    "ContextBoundary",
    "InstructionBoundary",
    "TrustClassifier",
    "ContextIntegrityEngine",
    "ContextItem",
    "UserIdentity",
    "InstructionType",
    "SourceCategory",
    "TrustLevel",
    "SecurityDecision",
    "TrustLabel",
    "IntegrityStatus",
    "ContextIntegrityResult",
    "INSTRUCTION_PRIORITIES",
    "PrivilegeIsolator",
    "TokenManager",
]
