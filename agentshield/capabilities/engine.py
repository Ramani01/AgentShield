"""
Capability Enforcement Engine for AgentShield v2 (Phase 21).
"""

import re
from typing import Dict, Any, Optional, List
from agentshield.context.models import SecurityDecision, UserIdentity
from agentshield.provenance.logger import AuditLogger
from agentshield.capabilities.models import (
    AgentCapability,
    CapabilityGrant,
    AgentCapabilityProfile,
    CapabilityCheckRequest,
    CapabilityCheckResult
)


class CapabilityEngine:
    """
    Enforces least-privilege capability profiles and blocks capability escalation attempts.
    Coordinates authorization before downstream Phase 1-20 security controls.
    """

    ESCALATION_PATTERNS = [
        r"(?i)grant_capability",
        r"(?i)enable_capability",
        r"(?i)override_capabilities",
        r"(?i)set_capability_profile",
        r"(?i)capabilities\s*=\s*ALL",
        r"(?i)grant_all_permissions",
        r"(?i)elevate_privileges",
        r"(?i)admin_override\s*:\s*capability"
    ]

    def __init__(self, audit_logger: Optional[AuditLogger] = None, strict_mode: bool = False):
        self.audit_logger = audit_logger or AuditLogger()
        self.strict_mode = strict_mode
        self._profiles: Dict[str, AgentCapabilityProfile] = {}

    def register_profile(self, profile: AgentCapabilityProfile) -> None:
        """Registers an authoritative, immutable capability profile for an agent."""
        key = f"{profile.tenant_id}:{profile.agent_id}"
        self._profiles[key] = profile
        self.audit_logger.log_event(
            "CAPABILITY_PROFILE_REGISTERED",
            {
                "profile_id": profile.profile_id,
                "agent_id": profile.agent_id,
                "tenant_id": profile.tenant_id,
                "granted_capabilities": [c.value for c, g in profile.grants.items() if g.granted]
            },
            tenant_id=profile.tenant_id
        )

    def get_profile(self, agent_id: str = "default_agent", tenant_id: str = "default") -> Optional[AgentCapabilityProfile]:
        """Retrieves registered capability profile for agent and tenant scope."""
        key = f"{tenant_id}:{agent_id}"
        return self._profiles.get(key)

    def check_capability(self, request: CapabilityCheckRequest) -> CapabilityCheckResult:
        """
        Validates whether a requested operation capability is authorized under least privilege.
        """
        tenant_id = request.tenant_id or (request.identity.tenant_id if request.identity else "default")
        agent_id = request.agent_id

        # 1. Scan context payload for capability escalation attempts
        context_str = str(request.context_data)
        for pattern in self.ESCALATION_PATTERNS:
            if re.search(pattern, context_str):
                self.audit_logger.log_event(
                    "CAPABILITY_ESCALATION_BLOCKED",
                    {
                        "agent_id": agent_id,
                        "capability": request.capability.value,
                        "pattern": pattern
                    },
                    tenant_id=tenant_id
                )
                return CapabilityCheckResult(
                    capability=request.capability,
                    allowed=False,
                    decision=SecurityDecision.DENY,
                    reason=f"Capability escalation attempt detected matching pattern '{pattern}'",
                    violations=["CAPABILITY_ESCALATION_ATTEMPT"]
                )

        # 2. Retrieve agent profile
        profile = self.get_profile(agent_id=agent_id, tenant_id=tenant_id)
        if not profile:
            if self.strict_mode:
                # Least privilege strict mode: No profile registered -> DENY
                self.audit_logger.log_event(
                    "CAPABILITY_DENIED",
                    {
                        "agent_id": agent_id,
                        "capability": request.capability.value,
                        "reason": "No registered capability profile found (Least Privilege DENY)"
                    },
                    tenant_id=tenant_id
                )
                return CapabilityCheckResult(
                    capability=request.capability,
                    allowed=False,
                    decision=SecurityDecision.DENY,
                    reason="No capability profile registered for agent (Least Privilege DENY)",
                    violations=["CAPABILITY_NOT_GRANTED"]
                )
            else:
                # Baseline mode: Allow unprofiled agents (100% Phase 1-20 backward compatible)
                return CapabilityCheckResult(
                    capability=request.capability,
                    allowed=True,
                    decision=SecurityDecision.ALLOW,
                    reason="No explicit capability profile registered; permitted under baseline mode",
                    violations=[]
                )

        # 3. Check grant in profile
        is_granted = profile.is_capability_granted(request.capability, target=request.target)
        if not is_granted:
            self.audit_logger.log_event(
                "CAPABILITY_DENIED",
                {
                    "agent_id": agent_id,
                    "capability": request.capability.value,
                    "target": request.target,
                    "reason": f"Capability {request.capability.value} is not granted in profile"
                },
                tenant_id=tenant_id
            )
            return CapabilityCheckResult(
                capability=request.capability,
                allowed=False,
                decision=SecurityDecision.DENY,
                reason=f"Capability '{request.capability.value}' is not granted to agent profile",
                violations=["CAPABILITY_UNAUTHORIZED"]
            )

        # 4. Capability Granted
        self.audit_logger.log_event(
            "CAPABILITY_ALLOWED",
            {
                "agent_id": agent_id,
                "capability": request.capability.value,
                "target": request.target
            },
            tenant_id=tenant_id
        )

        return CapabilityCheckResult(
            capability=request.capability,
            allowed=True,
            decision=SecurityDecision.ALLOW,
            reason=f"Capability '{request.capability.value}' authorized by agent profile"
        )
