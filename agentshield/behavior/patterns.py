"""
Phase 24: Behavior Pattern Definitions and Registry.
Defensive synthetic patterns for detecting multi-step agent behavior.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from agentshield.behavior.models import BehaviorEventType


@dataclass
class BehaviorPattern:
    """Configurable behavioral detection pattern."""
    pattern_id: str
    name: str
    description: str
    required_sequence: List[str]
    allow_gaps: bool = True
    max_gap: int = 5
    min_sequence_length: int = 2
    risk_level: str = "HIGH"
    confidence: float = 0.90
    recommended_decision: str = "REVIEW"
    scoped_tenant_id: Optional[str] = None
    scoped_agent_id: Optional[str] = None
    required_capability: Optional[str] = None
    required_trust_level: Optional[str] = None
    metadata: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not self.min_sequence_length:
            self.min_sequence_length = len(self.required_sequence)


class PatternRegistry:
    """Registry for managing active behavior detection patterns."""

    def __init__(self, include_defaults: bool = True):
        self._patterns: Dict[str, BehaviorPattern] = {}
        if include_defaults:
            self._load_default_patterns()

    def register_pattern(self, pattern: BehaviorPattern) -> None:
        """Registers or updates a behavioral pattern."""
        if not pattern or not pattern.pattern_id:
            raise ValueError("Invalid pattern or pattern_id")
        self._patterns[pattern.pattern_id] = pattern

    def get_pattern(self, pattern_id: str) -> Optional[BehaviorPattern]:
        """Retrieves pattern by ID."""
        return self._patterns.get(pattern_id)

    def list_patterns(self) -> List[BehaviorPattern]:
        """Returns all registered patterns."""
        return list(self._patterns.values())

    def remove_pattern(self, pattern_id: str) -> bool:
        """Removes a pattern by ID."""
        return self._patterns.pop(pattern_id, None) is not None

    def clear(self) -> None:
        """Clears all patterns."""
        self._patterns.clear()

    def _load_default_patterns(self) -> None:
        """Loads default synthetic defensive detection patterns."""
        defaults = [
            # Pattern A — Sensitive Data Escalation
            BehaviorPattern(
                pattern_id="BEHAVIOR-001",
                name="Sensitive Data Escalation",
                description="Agent reads unvalidated document, inspects long-term memory, then exports data.",
                required_sequence=[
                    BehaviorEventType.READ_DOCUMENT,
                    BehaviorEventType.READ_MEMORY,
                    BehaviorEventType.DATA_EXPORT
                ],
                allow_gaps=True,
                max_gap=5,
                risk_level="HIGH",
                confidence=0.92,
                recommended_decision="REVIEW"
            ),
            # Pattern B — Tool-to-Egress Chain
            BehaviorPattern(
                pattern_id="BEHAVIOR-002",
                name="Tool-to-Egress Chain",
                description="Agent reads document, executes a tool, then initiates external communication.",
                required_sequence=[
                    BehaviorEventType.READ_DOCUMENT,
                    BehaviorEventType.USE_TOOL,
                    BehaviorEventType.EXTERNAL_COMMUNICATION
                ],
                allow_gaps=True,
                max_gap=5,
                risk_level="HIGH",
                confidence=0.90,
                recommended_decision="REVIEW"
            ),
            # Pattern C — Configuration-to-Egress Chain
            BehaviorPattern(
                pattern_id="BEHAVIOR-003",
                name="Configuration-to-Egress Chain",
                description="Agent modifies security/system config, runs a tool, and opens external egress.",
                required_sequence=[
                    BehaviorEventType.MODIFY_CONFIGURATION,
                    BehaviorEventType.USE_TOOL,
                    BehaviorEventType.EXTERNAL_COMMUNICATION
                ],
                allow_gaps=True,
                max_gap=3,
                risk_level="CRITICAL",
                confidence=0.95,
                recommended_decision="DENY"
            ),
            # Pattern D — Broad Data Movement
            BehaviorPattern(
                pattern_id="BEHAVIOR-004",
                name="Broad Data Movement",
                description="Multi-source read (memory & doc) followed by data export and external communication.",
                required_sequence=[
                    BehaviorEventType.READ_MEMORY,
                    BehaviorEventType.READ_DOCUMENT,
                    BehaviorEventType.DATA_EXPORT,
                    BehaviorEventType.EXTERNAL_COMMUNICATION
                ],
                allow_gaps=True,
                max_gap=5,
                risk_level="CRITICAL",
                confidence=0.98,
                recommended_decision="DENY"
            ),
            # Pattern E — Memory Tamper and Egress
            BehaviorPattern(
                pattern_id="BEHAVIOR-005",
                name="Memory Tamper and Egress",
                description="Agent writes to memory, modifies configuration, and communicates externally.",
                required_sequence=[
                    BehaviorEventType.WRITE_MEMORY,
                    BehaviorEventType.MODIFY_CONFIGURATION,
                    BehaviorEventType.EXTERNAL_COMMUNICATION
                ],
                allow_gaps=True,
                max_gap=4,
                risk_level="HIGH",
                confidence=0.91,
                recommended_decision="REVIEW"
            )
        ]
        for p in defaults:
            self.register_pattern(p)
