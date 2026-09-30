"""
Phase 28: Safe Adversarial Simulation Executor.
Executes synthetic simulation scenarios against AgentShield controls without real side effects.
"""

import time
import logging
from typing import Optional, Dict, Any, List
from typing import Optional, Dict, Any, List
from agentshield.simulation.models import (
    SimulationScenario,
    SimulationEvent,
    SimulationStep,
    SimulationResult,
    SimulationOutcomeStatus
)
from agentshield.simulation.scenarios import ScenarioRegistry
from agentshield.simulation.generator import SimulationGenerator
from agentshield.evaluation.containment_models import EvidenceRecord, EvaluationSeverity, EvaluationOutcome
from agentshield.capabilities.models import AgentCapability, CapabilityCheckRequest

logger = logging.getLogger("AgentShield.SimulationExecutor")


class SimulationExecutor:
    """
    Executes safe adversarial agent simulations.

    Safety Invariants Enforced:
    1. No Shell Execution: Never executes subprocess, cmd, or shell commands.
    2. No Network Execution: Makes no HTTP requests, socket calls, or external network I/O.
    3. No Infrastructure Modification: Does not alter operating system isolation, containers, or firewalls.
    4. No Authorization Escalation: Does not grant capabilities or alter authoritative containment state.
    5. Simulation Only Marker: Sets simulation_only = True on all synthetic events.
    6. Tenant & Agent Isolation: Scopes all evaluations to explicit (tenant_id, agent_id).
    """

    def __init__(
        self,
        shield: Optional[Any] = None,
        registry: Optional[ScenarioRegistry] = None,
        generator: Optional[SimulationGenerator] = None
    ):
        if shield is None:
            from agentshield import AgentShield
            shield = AgentShield()
        self.shield = shield
        self.registry = registry or ScenarioRegistry(include_defaults=True)
        self.generator = generator or SimulationGenerator(registry=self.registry)

    def execute_scenario(
        self,
        scenario_id: str,
        tenant_id: str = "default",
        agent_id: str = "default"
    ) -> SimulationResult:
        """
        Executes a safe adversarial simulation scenario by ID and returns evaluation result.
        """
        scenario = self.registry.get_scenario(scenario_id)
        events = self.generator.generate_events_for_scenario(scenario_id, tenant_id=tenant_id, agent_id=agent_id)

        step_results: List[SimulationStep] = []
        actual_signal = "UNKNOWN_SIGNAL"
        actual_outcome = EvaluationOutcome.NO_ACTION
        actual_isolation = "NONE"
        matched_rules: List[str] = []
        evidence_ids: List[str] = []
        explanation_parts: List[str] = []

        # Execute safe synthetic evaluation based on scenario type
        for idx, ev in enumerate(events):
            step = SimulationStep(
                step_id=f"step_{idx+1}",
                step_number=idx + 1,
                description=f"Synthetic event evaluation step {idx+1} for {scenario.scenario_id}",
                event=ev,
                expected_signal=ev.expected_signal
            )

            payload = ev.payload
            event_type = ev.event_type

            if scenario.scenario_type == "CAPABILITY_ESCALATION":
                # Safe capability check against Phase 21 CapabilityEngine with escalation context
                cap_enum = AgentCapability.DATA_EXPORT
                try:
                    if "capability" in payload:
                        cap_enum = AgentCapability(payload["capability"])
                except ValueError:
                    cap_enum = AgentCapability.DATA_EXPORT

                cap_req = CapabilityCheckRequest(
                    capability=cap_enum,
                    agent_id=agent_id,
                    tenant_id=tenant_id,
                    target=payload.get("target", "unauthorized_target"),
                    context_data={"escalation": "grant_all_permissions"}  # Triggers capability denial
                )
                res = self.shield.capability_engine.check_capability(cap_req)
                actual_signal = "CAPABILITY_DENIED" if not res.allowed else "CAPABILITY_ALLOWED"

                ev_rec = EvidenceRecord(
                    source_phase="Phase-21",
                    source_control="PHASE_21_CAPABILITY_ENGINE",
                    evidence_type="CAPABILITY_ESCALATION_ATTEMPT",
                    severity=EvaluationSeverity.HIGH,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    references={"capability": cap_enum.value, "allowed": res.allowed}
                )
                assessment = self.shield.evaluation_engine.evaluate_evidence(tenant_id, agent_id, [ev_rec])
                actual_outcome = assessment.outcome
                actual_isolation = assessment.recommended_isolation_level
                matched_rules = assessment.matched_rules
                evidence_ids = assessment.evidence_ids
                step.observed_signal = actual_signal
                step.matched = (actual_signal == scenario.expected_signal)
                step_results.append(step)

            elif scenario.scenario_type == "POLICY_DENIAL":
                # Safe communication policy check against Phase 22 CommunicationPolicyEngine
                from agentshield.communication.models import CommunicationRequest, CommunicationPrincipal, PrincipalType, CommunicationType
                src_p = CommunicationPrincipal(principal_id=agent_id, principal_type=PrincipalType.AGENT, name="SimAgent", tenant_id=tenant_id)
                dest_p = CommunicationPrincipal(principal_id="untrusted_node", principal_type=PrincipalType.UNKNOWN_SERVICE, name="UntrustedNode", tenant_id="external_tenant")
                comm_req = CommunicationRequest(source=src_p, destination=dest_p, comm_type=CommunicationType.AGENT_TO_SERVICE)

                comm_res = self.shield.communication_engine.evaluate_communication(comm_req)
                actual_signal = "COMMUNICATION_DENY" if not comm_res.allowed else "COMMUNICATION_ALLOW"

                ev_rec = EvidenceRecord(
                    source_phase="Phase-22",
                    source_control="PHASE_22_COMMUNICATION_POLICY",
                    evidence_type="POLICY_DENIAL",
                    severity=EvaluationSeverity.HIGH,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    references={"target_domain": payload.get("target_domain", "untrusted-exfil-node.org"), "decision": "DENY"}
                )
                assessment = self.shield.evaluation_engine.evaluate_evidence(tenant_id, agent_id, [ev_rec])
                actual_outcome = assessment.outcome
                actual_isolation = assessment.recommended_isolation_level
                matched_rules = assessment.matched_rules
                evidence_ids = assessment.evidence_ids
                step.observed_signal = actual_signal
                step.matched = (actual_signal == scenario.expected_signal)
                step_results.append(step)

            elif scenario.scenario_type == "BEHAVIORAL_RISK":
                # Safe synthetic behavioral detection signal
                ev_rec = EvidenceRecord(
                    source_phase="Phase-24",
                    source_control="PHASE_24_BEHAVIORAL_DETECTOR",
                    evidence_type="BEHAVIOR_PATTERN",
                    severity=EvaluationSeverity.CRITICAL,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    references={"pattern_id": payload.get("pattern_id", "BEHAVIOR-004"), "risk_level": "CRITICAL"}
                )
                assessment = self.shield.evaluation_engine.evaluate_evidence(tenant_id, agent_id, [ev_rec])
                actual_signal = "BEHAVIOR_PATTERN_MATCH"
                actual_outcome = assessment.outcome
                actual_isolation = assessment.recommended_isolation_level
                matched_rules = assessment.matched_rules
                evidence_ids = assessment.evidence_ids
                step.observed_signal = actual_signal
                step.matched = (actual_outcome == scenario.expected_outcome)
                step_results.append(step)

            elif scenario.scenario_type == "RUNTIME_DRIFT":
                # Safe synthetic runtime integrity signal
                ev_rec = EvidenceRecord(
                    source_phase="Phase-23",
                    source_control="PHASE_23_RUNTIME_INTEGRITY",
                    evidence_type="RUNTIME_INTEGRITY",
                    severity=EvaluationSeverity.CRITICAL,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    references={"integrity_state": payload.get("integrity_state", "INVALID")}
                )
                assessment = self.shield.evaluation_engine.evaluate_evidence(tenant_id, agent_id, [ev_rec])
                actual_signal = "RUNTIME_INTEGRITY_INVALID"
                actual_outcome = assessment.outcome
                actual_isolation = assessment.recommended_isolation_level
                matched_rules = assessment.matched_rules
                evidence_ids = assessment.evidence_ids
                step.observed_signal = actual_signal
                step.matched = (actual_outcome == scenario.expected_outcome)
                step_results.append(step)

            elif scenario.scenario_type == "GRAPH_RISK":
                # Safe synthetic graph path signal
                ev_rec = EvidenceRecord(
                    source_phase="Phase-26",
                    source_control="PHASE_26_SECURITY_GRAPH",
                    evidence_type="SECURITY_GRAPH_PATH",
                    severity=EvaluationSeverity.HIGH,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    references={"risk_level": "HIGH", "signals": payload.get("signals", ["UNAUTHORIZED_TARGET"])}
                )
                assessment = self.shield.evaluation_engine.evaluate_evidence(tenant_id, agent_id, [ev_rec])
                actual_signal = "SECURITY_GRAPH_PATH_SUSPICIOUS"
                actual_outcome = assessment.outcome
                actual_isolation = assessment.recommended_isolation_level
                matched_rules = assessment.matched_rules
                evidence_ids = assessment.evidence_ids
                step.observed_signal = actual_signal
                step.matched = (actual_outcome == scenario.expected_outcome)
                step_results.append(step)

            elif scenario.scenario_type == "CONTAINMENT_ESCALATION":
                # Combined synthetic evidence: invalid runtime + critical behavior
                ev_rt = EvidenceRecord(
                    source_phase="Phase-23",
                    evidence_type="RUNTIME_INTEGRITY",
                    severity=EvaluationSeverity.CRITICAL,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    references={"integrity_state": "INVALID"}
                )
                ev_beh = EvidenceRecord(
                    source_phase="Phase-24",
                    evidence_type="BEHAVIOR_PATTERN",
                    severity=EvaluationSeverity.CRITICAL,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    references={"pattern_id": "BEHAVIOR-004"}
                )
                assessment = self.shield.evaluation_engine.evaluate_evidence(tenant_id, agent_id, [ev_rt, ev_beh])
                actual_signal = "CONTAINMENT_ESCALATE_RECOMMENDED"
                actual_outcome = assessment.outcome
                actual_isolation = assessment.recommended_isolation_level
                matched_rules = assessment.matched_rules
                evidence_ids = assessment.evidence_ids
                step.observed_signal = actual_signal
                step.matched = (actual_outcome == scenario.expected_outcome)
                step_results.append(step)

            elif scenario.scenario_type == "RECOVERY_REVIEW":
                # Synthetic recovery request condition
                ev_rt = EvidenceRecord(
                    source_phase="Phase-23",
                    evidence_type="RUNTIME_INTEGRITY",
                    severity=EvaluationSeverity.LOW,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    references={"integrity_state": "VALID"}
                )
                ctx = {"current_containment_state": "CONTAINED", "has_recovery_request": True}
                assessment = self.shield.evaluation_engine.evaluate_evidence(tenant_id, agent_id, [ev_rt], context=ctx)
                actual_signal = "CONTAINMENT_RELEASE_REVIEW_RECOMMENDED"
                actual_outcome = assessment.outcome
                actual_isolation = assessment.recommended_isolation_level
                matched_rules = assessment.matched_rules
                evidence_ids = assessment.evidence_ids
                step.observed_signal = actual_signal
                step.matched = (actual_outcome == scenario.expected_outcome)
                step_results.append(step)

            else:
                step.observed_signal = "UNKNOWN_SCENARIO_TYPE"
                step.matched = False
                step_results.append(step)

        # Determine overall simulation pass/fail status
        signal_matches = (actual_signal == scenario.expected_signal)
        outcome_matches = (actual_outcome == scenario.expected_outcome)

        status = SimulationOutcomeStatus.PASS if (signal_matches and outcome_matches) else SimulationOutcomeStatus.FAIL

        explanation = (
            f"Simulation '{scenario.scenario_id}' status {status}. "
            f"Expected signal '{scenario.expected_signal}', observed '{actual_signal}'. "
            f"Expected outcome '{scenario.expected_outcome}', observed '{actual_outcome}'."
        )

        # Log audit entry
        if self.shield.pipeline.audit_logger:
            self.shield.pipeline.audit_logger.log_event(
                "ADVERSARIAL_SIMULATION_EXECUTED",
                {
                    "scenario_id": scenario.scenario_id,
                    "status": status,
                    "tenant_id": tenant_id,
                    "agent_id": agent_id,
                    "expected_signal": scenario.expected_signal,
                    "actual_signal": actual_signal,
                    "expected_outcome": scenario.expected_outcome,
                    "actual_outcome": actual_outcome
                },
                tenant_id=tenant_id
            )

        return SimulationResult(
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            tenant_id=tenant_id,
            agent_id=agent_id,
            status=status,
            expected_signal=scenario.expected_signal,
            actual_signal=actual_signal,
            expected_outcome=scenario.expected_outcome,
            actual_outcome=actual_outcome,
            expected_isolation_level=scenario.expected_isolation_level,
            actual_isolation_level=actual_isolation,
            matched_rules=matched_rules,
            evidence_ids=evidence_ids,
            explanation=explanation,
            step_results=step_results,
            metadata={
                "target_phase": scenario.target_phase,
                "simulation_only": True
            }
        )
