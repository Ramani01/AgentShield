"""
Communication Policy Engine for Phase 22 Agent Communication & Service Policy.
Governs agent-to-agent, agent-to-service, and service-to-service communication rules.
"""

import re
import json
from typing import Dict, Any, Optional, List
from agentshield.context.models import SecurityDecision, UserIdentity
from agentshield.provenance.logger import AuditLogger
from agentshield.capabilities.models import AgentCapability, CapabilityCheckRequest
from agentshield.communication.models import (
    PrincipalType,
    CommunicationType,
    CommunicationPrincipal,
    CommunicationPolicyRule,
    CommunicationRequest,
    CommunicationDecisionResult
)


class CommunicationPolicyEngine:
    """
    Central evaluator enforcing communication permissions, principal isolation,
    tenant boundaries, and capability integration across agents and services.
    """

    ESCALATION_PATTERNS = [
        r"(?i)bypass_communication_policy",
        r"(?i)override_tenant_isolation",
        r"(?i)allow_all_principals",
        r"(?i)grant_communication_access",
        r"(?i)disable_communication_policy",
        r"(?i)cross_tenant_override"
    ]

    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        capability_engine: Optional[Any] = None,
        strict_mode: bool = False
    ):
        self.audit_logger = audit_logger or AuditLogger()
        self.capability_engine = capability_engine
        self.strict_mode = strict_mode
        self._principals: Dict[str, CommunicationPrincipal] = {}
        self._rules: List[CommunicationPolicyRule] = []

    def register_principal(self, principal: CommunicationPrincipal) -> None:
        """Registers a communication principal."""
        key = f"{principal.tenant_id}:{principal.principal_id}"
        self._principals[key] = principal

    def get_principal(self, principal_id: str, tenant_id: str = "default") -> Optional[CommunicationPrincipal]:
        """Retrieves a registered principal by ID and tenant scope."""
        key = f"{tenant_id}:{principal_id}"
        return self._principals.get(key)

    def add_rule(self, rule: CommunicationPolicyRule) -> None:
        """Appends a communication policy rule."""
        self._rules.append(rule)

    def evaluate_communication(self, request: CommunicationRequest) -> CommunicationDecisionResult:
        """
        Evaluates a proposed communication request against context integrity,
        unknown principals, tenant isolation, Phase 21 capabilities, and policy rules.
        """
        source = request.source
        destination = request.destination
        tenant_id = source.tenant_id or (request.identity.tenant_id if request.identity else "default")

        # 1. Protection against untrusted context escalation attempts
        if request.context_data:
            context_str = json.dumps(request.context_data)
            for pattern in self.ESCALATION_PATTERNS:
                if re.search(pattern, context_str):
                    self.audit_logger.log_event(
                        "COMMUNICATION_POLICY_VIOLATION",
                        {
                            "source_id": source.principal_id,
                            "destination_id": destination.principal_id,
                            "matched_pattern": pattern,
                            "reason": "Untrusted context attempted communication policy escalation"
                        },
                        tenant_id=tenant_id
                    )
                    self.audit_logger.log_event(
                        "COMMUNICATION_DENIED",
                        {
                            "source_id": source.principal_id,
                            "destination_id": destination.principal_id,
                            "reason": f"Escalation attempt detected matching pattern '{pattern}'"
                        },
                        tenant_id=tenant_id
                    )
                    return CommunicationDecisionResult(
                        allowed=False,
                        decision=SecurityDecision.DENY,
                        reason=f"Communication policy escalation attempt detected matching pattern '{pattern}'",
                        violations=["COMMUNICATION_POLICY_ESCALATION"]
                    )

        # 2. Unknown Principal Check
        if source.principal_type == PrincipalType.UNKNOWN_SERVICE or destination.principal_type == PrincipalType.UNKNOWN_SERVICE:
            self.audit_logger.log_event(
                "UNKNOWN_PRINCIPAL_BLOCKED",
                {
                    "source_id": source.principal_id,
                    "source_type": source.principal_type.value,
                    "destination_id": destination.principal_id,
                    "destination_type": destination.principal_type.value
                },
                tenant_id=tenant_id
            )
            self.audit_logger.log_event(
                "COMMUNICATION_DENIED",
                {
                    "source_id": source.principal_id,
                    "destination_id": destination.principal_id,
                    "reason": "Communication involving UNKNOWN_SERVICE principal blocked"
                },
                tenant_id=tenant_id
            )
            return CommunicationDecisionResult(
                allowed=False,
                decision=SecurityDecision.DENY,
                reason="Communication involving UNKNOWN_SERVICE principal is denied",
                violations=["UNKNOWN_PRINCIPAL_BLOCKED"]
            )

        # 3. Tenant Isolation Check
        is_same_tenant = (source.tenant_id == destination.tenant_id)
        if not is_same_tenant:
            # Check if there is an explicit CROSS_TENANT rule allowing this
            cross_tenant_allowed = False
            for rule in self._rules:
                if rule.tenant_relationship in ("CROSS_TENANT", "ANY") and rule.decision == SecurityDecision.ALLOW:
                    if self._matches_rule_principals(request, rule):
                        cross_tenant_allowed = True
                        break

            if not cross_tenant_allowed:
                self.audit_logger.log_event(
                    "CROSS_TENANT_COMMUNICATION_BLOCKED",
                    {
                        "source_id": source.principal_id,
                        "source_tenant": source.tenant_id,
                        "destination_id": destination.principal_id,
                        "destination_tenant": destination.tenant_id
                    },
                    tenant_id=tenant_id
                )
                self.audit_logger.log_event(
                    "COMMUNICATION_DENIED",
                    {
                        "source_id": source.principal_id,
                        "destination_id": destination.principal_id,
                        "reason": f"Cross-tenant communication from '{source.tenant_id}' to '{destination.tenant_id}' blocked"
                    },
                    tenant_id=tenant_id
                )
                return CommunicationDecisionResult(
                    allowed=False,
                    decision=SecurityDecision.DENY,
                    reason=f"Cross-tenant communication from '{source.tenant_id}' to '{destination.tenant_id}' is denied",
                    violations=["CROSS_TENANT_COMMUNICATION_BLOCKED"]
                )

        # 4. Phase 21 Capability Integration Check
        if self.capability_engine:
            required_capability = AgentCapability.EXTERNAL_COMMUNICATION
            if request.comm_type == CommunicationType.AGENT_TO_TOOL:
                required_capability = AgentCapability.USE_TOOLS

            cap_req = CapabilityCheckRequest(
                capability=required_capability,
                agent_id=source.principal_id,
                tenant_id=source.tenant_id,
                identity=request.identity,
                context_data=request.context_data
            )
            cap_res = self.capability_engine.check_capability(cap_req)
            if not cap_res.allowed:
                self.audit_logger.log_event(
                    "COMMUNICATION_DENIED",
                    {
                        "source_id": source.principal_id,
                        "destination_id": destination.principal_id,
                        "reason": f"Required capability {required_capability.value} denied by Phase 21 engine"
                    },
                    tenant_id=tenant_id
                )
                return CommunicationDecisionResult(
                    allowed=False,
                    decision=cap_res.decision,
                    reason=f"Required capability '{required_capability.value}' is not granted to agent",
                    violations=["COMMUNICATION_CAPABILITY_DENIED"]
                )

        # 5. Rule Evaluation
        for rule in self._rules:
            if self._matches_rule(request, rule):
                allowed = (rule.decision == SecurityDecision.ALLOW)
                event_name = f"COMMUNICATION_{rule.decision.value}"
                self.audit_logger.log_event(
                    event_name,
                    {
                        "source_id": source.principal_id,
                        "destination_id": destination.principal_id,
                        "comm_type": request.comm_type.value,
                        "matched_rule_id": rule.rule_id,
                        "reason": rule.reason
                    },
                    tenant_id=tenant_id
                )
                return CommunicationDecisionResult(
                    allowed=allowed,
                    decision=rule.decision,
                    reason=rule.reason,
                    matched_rule_id=rule.rule_id,
                    violations=[] if allowed else [f"COMMUNICATION_POLICY_{rule.decision.value}"]
                )

        # 6. Fallback Evaluation
        if self.strict_mode:
            self.audit_logger.log_event(
                "COMMUNICATION_DENIED",
                {
                    "source_id": source.principal_id,
                    "destination_id": destination.principal_id,
                    "reason": "No explicit matching communication policy rule found (Strict Mode)"
                },
                tenant_id=tenant_id
            )
            return CommunicationDecisionResult(
                allowed=False,
                decision=SecurityDecision.DENY,
                reason="No matching communication policy rule found (Strict Fail-Closed)",
                violations=["NO_COMMUNICATION_POLICY_MATCH"]
            )
        else:
            # Baseline same-tenant allow
            if is_same_tenant:
                self.audit_logger.log_event(
                    "COMMUNICATION_ALLOWED",
                    {
                        "source_id": source.principal_id,
                        "destination_id": destination.principal_id,
                        "reason": "Permitted under same-tenant default communication policy"
                    },
                    tenant_id=tenant_id
                )
                return CommunicationDecisionResult(
                    allowed=True,
                    decision=SecurityDecision.ALLOW,
                    reason="Permitted under same-tenant default communication policy",
                    violations=[]
                )
            else:
                self.audit_logger.log_event(
                    "COMMUNICATION_DENIED",
                    {
                        "source_id": source.principal_id,
                        "destination_id": destination.principal_id,
                        "reason": "Cross-tenant communication not permitted"
                    },
                    tenant_id=tenant_id
                )
                return CommunicationDecisionResult(
                    allowed=False,
                    decision=SecurityDecision.DENY,
                    reason="Cross-tenant communication not permitted",
                    violations=["CROSS_TENANT_COMMUNICATION_BLOCKED"]
                )

    def _matches_rule_principals(self, request: CommunicationRequest, rule: CommunicationPolicyRule) -> bool:
        """Helper to match source and destination principals against a rule."""
        if rule.source_principal_id and rule.source_principal_id != request.source.principal_id:
            return False
        if rule.source_type and rule.source_type != request.source.principal_type:
            return False
        if rule.destination_principal_id and rule.destination_principal_id != request.destination.principal_id:
            return False
        if rule.destination_type and rule.destination_type != request.destination.principal_type:
            return False
        return True

    def _matches_rule(self, request: CommunicationRequest, rule: CommunicationPolicyRule) -> bool:
        """Full match check including communication type, tenant relationship, and data classification."""
        if not self._matches_rule_principals(request, rule):
            return False

        if rule.comm_type and rule.comm_type != request.comm_type:
            return False

        if rule.tenant_relationship == "SAME_TENANT" and request.source.tenant_id != request.destination.tenant_id:
            return False

        if rule.tenant_relationship == "CROSS_TENANT" and request.source.tenant_id == request.destination.tenant_id:
            return False

        if rule.allowed_data_classifications and request.data_classification not in rule.allowed_data_classifications:
            return False

        return True
