"""
LangGraph-based state machine for incident resolution.
Replaces the manual state machine with a proper graph-based orchestration flow.

Uses LangGraph's StateGraph for ordered, deterministic state transitions:
  TRIAGE -> DIAGNOSIS -> REMEDIATION -> VERIFICATION -> RESOLVED/ESCALATED
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Literal, TypedDict

from langgraph.graph import END, StateGraph

from backend.shared.circuit_breaker import CostCircuitBreaker
from backend.shared.config import AppConfig, SentryMode
from backend.shared.interfaces import ILLMClient, IMemoryStore, IToolExecutor
from backend.shared.models import (
    ActivityType, Incident, IncidentSeverity, IncidentState, ToolCall,
)
from backend.orchestrator.schemas import (
    DiagnosisResult, RemediationResult, TriageResult, VerificationResult,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Graph State: typed dict that flows through every node
# ---------------------------------------------------------------------------

class IncidentGraphState(TypedDict, total=False):
    """State that flows through the LangGraph nodes."""
    incident: Incident
    triage: dict          # TriageResult as dict
    diagnosis: dict       # DiagnosisResult as dict
    remediation: dict     # RemediationResult as dict
    verification: dict    # VerificationResult as dict
    tool_results: list    # Accumulated tool call results
    tool_loop_count: int  # How many diagnosis tool loops we've done
    error: str            # Error message if any node fails


# ---------------------------------------------------------------------------
# Node functions - each is a pure(ish) function that transforms state
# ---------------------------------------------------------------------------

def _build_triage_prompt(incident: Incident, history: list) -> str:
    hist_text = ""
    if history:
        hist_text = "\n\nSimilar past incidents:\n"
        for h in history[:3]:
            hist_text += f"- {h.symptom} -> {h.root_cause} -> Fix: {h.fix}\n"

    return (
        f"You are Claude Sentry, an autonomous server monitoring AI.\n"
        f"Triage this production error log entry:\n\n"
        f"ERROR: {incident.symptom}\n"
        f"{hist_text}\n"
        f"Respond in this EXACT format:\n"
        f"SEVERITY: <low|medium|high|critical>\n"
        f"VERDICT: <INVESTIGATE|FALSE POSITIVE>\n"
        f"SUMMARY: <one-line description of the issue>\n\n"
        f"IMPORTANT: Only use 'VERDICT: FALSE POSITIVE' for truly benign log entries. "
        f"Any actual error, exception, or service degradation MUST be 'VERDICT: INVESTIGATE'."
    )


def _build_diagnosis_prompt(incident: Incident, config: AppConfig) -> str:
    is_audit = config.security.mode == SentryMode.AUDIT
    audit_note = ""
    if is_audit:
        audit_note = (
            "\n\nIMPORTANT: System is in AUDIT mode. Active tools will only log intent. "
            "Read-only tools work normally. Focus on read-only investigation first, "
            "then provide your best diagnosis."
        )
    return (
        f"You are diagnosing a server incident.\n"
        f"Symptom: {incident.symptom}\n"
        f"Severity: {incident.severity.value}\n\n"
        f"Use the available tools to investigate. "
        f"Find the root cause. Be specific.{audit_note}"
    )


def _build_diagnosis_summary_prompt(
    incident: Incident, tool_results: list, is_audit: bool
) -> str:
    results_text = "\n".join(f"  - {r}" for r in tool_results[-20:])
    audit_note = ""
    if is_audit:
        audit_note = (
            "\nNote: System is in AUDIT mode. Provide best-effort diagnosis "
            "based on error symptoms and any files successfully read."
        )
    return (
        f"Provide your FINAL DIAGNOSIS for this incident.\n\n"
        f"Symptom: {incident.symptom}\n"
        f"Severity: {incident.severity.value}\n"
        f"Triage: {incident.triage_result or 'N/A'}\n\n"
        f"Investigation results:\n{results_text}\n{audit_note}\n\n"
        f"DO NOT request any more tools. Provide analysis now:\n"
        f"ROOT CAUSE: <what is wrong>\n"
        f"RECOMMENDED FIX: <what to do>"
    )


def _build_remediation_prompt(incident: Incident, is_audit: bool) -> str:
    if is_audit:
        return (
            f"Root cause: {incident.root_cause}\n"
            f"Symptom: {incident.symptom}\n\n"
            f"System is in AUDIT mode. Describe the fix you WOULD apply. "
            f"Do NOT call any tools. Just describe the plan.\n"
            f"End with: FIX PROPOSED: <one-line summary>"
        )
    return (
        f"Root cause: {incident.root_cause}\n"
        f"Symptom: {incident.symptom}\n\n"
        f"Propose and apply a fix. Be conservative - prefer restarts over code changes."
    )


def _build_verify_prompt(incident: Incident, is_audit: bool) -> str:
    if is_audit:
        return (
            f"Incident: {incident.symptom}\n"
            f"Proposed fix: {incident.fix_applied or 'Audit plan provided'}\n\n"
            f"System is in AUDIT mode - no fix was applied. "
            f"The diagnosis and plan have been recorded. Reply 'resolved'."
        )
    return (
        f"Incident: {incident.symptom}\n"
        f"Fix applied: {incident.fix_applied}\n\n"
        f"Is this issue resolved? Reply 'fixed' or 'not fixed'."
    )


# ---------------------------------------------------------------------------
# Graph Builder - creates the compiled LangGraph
# ---------------------------------------------------------------------------

class IncidentGraphBuilder:
    """
    Builds a LangGraph StateGraph for incident resolution.

    Each node corresponds to a phase in the design doc state machine:
      triage_node -> route_triage -> diagnosis_node -> remediation_node
                                                    -> verification_node -> route_verify
    """

    def __init__(
        self,
        config: AppConfig,
        llm: ILLMClient,
        tools: IToolExecutor,
        memory: IMemoryStore,
        circuit_breaker: CostCircuitBreaker,
    ):
        self._config = config
        self._llm = llm
        self._tools = tools
        self._memory = memory
        self._cb = circuit_breaker

    def build(self):
        """Build and compile the LangGraph StateGraph."""
        graph = StateGraph(IncidentGraphState)

        # Add nodes
        graph.add_node("triage", self._triage_node)
        graph.add_node("diagnosis", self._diagnosis_node)
        graph.add_node("remediation", self._remediation_node)
        graph.add_node("verification", self._verification_node)

        # Set entry point
        graph.set_entry_point("triage")

        # Conditional edges
        graph.add_conditional_edges(
            "triage",
            self._route_after_triage,
            {"diagnosis": "diagnosis", "end": END},
        )
        graph.add_edge("diagnosis", "remediation")
        graph.add_edge("remediation", "verification")
        graph.add_conditional_edges(
            "verification",
            self._route_after_verification,
            {"end": END, "diagnosis": "diagnosis"},
        )

        return graph.compile()

    # ── Node implementations ─────────────────────────────

    async def _triage_node(self, state: IncidentGraphState) -> IncidentGraphState:
        """Phase 1: Quick severity assessment (low effort)."""
        incident = state["incident"]
        incident.state = IncidentState.TRIAGE
        incident.current_agent_action = "Analyzing error severity..."
        incident.log_activity(ActivityType.PHASE_START, "triage", "Triage phase started",
                              detail="Quick severity assessment using low-effort analysis")

        try:
            relevant = await self._memory.get_relevant(
                incident.symptom.lower().split()[:5]
            )
            if relevant:
                incident.log_activity(ActivityType.INFO, "triage",
                                      f"Found {len(relevant)} similar past incidents",
                                      detail="; ".join(h.symptom[:60] for h in relevant[:3]))

            prompt = _build_triage_prompt(incident, relevant)
            incident.current_agent_action = "Calling Claude Opus 4.6 (effort: low)..."
            incident.log_activity(ActivityType.LLM_CALL, "triage",
                                  "Calling Claude Opus 4.6 for triage",
                                  metadata={"effort": "low"})

            response = await self._llm.analyze(prompt, effort="low")
            self._track_cost(response)

            text = response.get("text", "")
            logger.info(f"Triage raw for {incident.id}: {text[:200]}")
            incident.log_activity(ActivityType.INFO, "triage", "LLM response received",
                                  detail=text[:300],
                                  metadata={"input_tokens": response.get("input_tokens", 0),
                                            "output_tokens": response.get("output_tokens", 0)})

            # Parse into structured result
            triage = TriageResult.parse_from_text(text)
            logger.info(
                f"Triage parsed for {incident.id}: "
                f"severity={triage.severity}, verdict={triage.verdict}, "
                f"summary={triage.summary[:100]}"
            )

            # Apply structured result to incident
            sev_map = {
                "critical": IncidentSeverity.CRITICAL,
                "high": IncidentSeverity.HIGH,
                "medium": IncidentSeverity.MEDIUM,
                "low": IncidentSeverity.LOW,
            }
            incident.severity = sev_map.get(triage.severity, IncidentSeverity.MEDIUM)
            incident.triage_result = triage.summary

            if triage.verdict == "FALSE_POSITIVE":
                incident.state = IncidentState.IDLE
                incident.log_activity(ActivityType.DECISION, "triage",
                                      "Classified as FALSE POSITIVE — ignoring",
                                      detail=triage.summary)
            else:
                incident.state = IncidentState.DIAGNOSIS
                incident.log_activity(ActivityType.DECISION, "triage",
                                      f"Classified as {triage.severity.upper()} — will investigate",
                                      detail=triage.summary)

            incident.log_activity(ActivityType.PHASE_COMPLETE, "triage", "Triage complete",
                                  metadata={"severity": triage.severity, "verdict": triage.verdict})
            incident.current_agent_action = None

            return {
                **state,
                "incident": incident,
                "triage": triage.model_dump(),
                "tool_results": [],
                "tool_loop_count": 0,
            }
        except Exception as e:
            logger.error(f"Triage error for {incident.id}: {e}")
            incident.log_activity(ActivityType.ERROR, "triage", f"Triage failed: {e}")
            incident.state = IncidentState.ESCALATED
            incident.current_agent_action = None
            return {**state, "incident": incident, "error": str(e)}

    async def _diagnosis_node(self, state: IncidentGraphState) -> IncidentGraphState:
        """Phase 2: Deep analysis with tool loop (high effort)."""
        incident = state["incident"]
        incident.state = IncidentState.DIAGNOSIS
        incident.current_agent_action = "Starting deep analysis..."
        incident.log_activity(ActivityType.PHASE_START, "diagnosis", "Diagnosis phase started",
                              detail="Deep root-cause analysis using high-effort reasoning with tool access")
        tool_results = state.get("tool_results", [])
        is_audit = self._config.security.mode == SentryMode.AUDIT

        try:
            tools = self._tools.get_tool_definitions()
            prompt = _build_diagnosis_prompt(incident, self._config)
            max_loops = self._config.security.max_retries

            for loop_idx in range(max_loops):
                if self._cb.is_tripped:
                    incident.log_activity(ActivityType.ERROR, "diagnosis", "Circuit breaker tripped — aborting")
                    incident.state = IncidentState.ESCALATED
                    incident.current_agent_action = None
                    return {**state, "incident": incident, "error": "circuit_breaker_tripped"}

                incident.current_agent_action = f"Calling Claude Opus 4.6 (effort: high, loop {loop_idx+1}/{max_loops})..."
                incident.log_activity(ActivityType.LLM_CALL, "diagnosis",
                                      f"LLM call #{loop_idx+1} (effort: high)",
                                      metadata={"effort": "high", "loop": loop_idx+1})

                response = await self._llm.analyze(prompt, effort="high", tools=tools)
                self._track_cost(response)

                tool_calls = response.get("tool_calls", [])
                if tool_calls:
                    for tc in tool_calls:
                        args_summary = ", ".join(f"{k}={str(v)[:50]}" for k, v in tc.get("arguments", {}).items())
                        incident.current_agent_action = f"Running tool: {tc['name']}({args_summary})..."
                        incident.log_activity(ActivityType.TOOL_CALL, "diagnosis",
                                              f"Calling {tc['name']}",
                                              detail=args_summary,
                                              metadata={"tool": tc["name"], "args": {k: str(v)[:100] for k, v in tc.get("arguments", {}).items()}})

                        call = ToolCall(tool_name=tc["name"], arguments=tc.get("arguments", {}))
                        result = await self._tools.execute(call)
                        result_text = result.output or result.error or ""
                        prompt += f"\n\nTool {tc['name']} result: {result_text}"
                        tool_results.append(f"{tc['name']}: {result_text[:200]}")

                        incident.log_activity(ActivityType.TOOL_RESULT, "diagnosis",
                                              f"{tc['name']} → {'✓' if result.success else '✗'}",
                                              detail=result_text[:300],
                                              metadata={"success": result.success, "audit_only": result.audit_only})

                    if is_audit and loop_idx >= 1:
                        incident.log_activity(ActivityType.INFO, "diagnosis",
                                              "AUDIT mode: forcing summary after tool loops")
                        break
                    continue

                # No tool calls - LLM gave text response
                text = response.get("text", "")
                if text:
                    diagnosis = DiagnosisResult.parse_from_text(text)
                    incident.root_cause = diagnosis.root_cause
                    incident.state = IncidentState.REMEDIATION
                    incident.log_activity(ActivityType.DECISION, "diagnosis",
                                          "Root cause identified",
                                          detail=diagnosis.root_cause,
                                          metadata={"recommended_fix": diagnosis.recommended_fix})
                    incident.log_activity(ActivityType.PHASE_COMPLETE, "diagnosis", "Diagnosis complete")
                    incident.current_agent_action = None
                    logger.info(f"Diagnosis for {incident.id}: {diagnosis.root_cause[:150]}")
                    return {
                        **state,
                        "incident": incident,
                        "diagnosis": diagnosis.model_dump(),
                        "tool_results": tool_results,
                    }

            # Exhausted loops - ask for best-effort summary
            incident.current_agent_action = "Synthesizing diagnosis from gathered evidence..."
            incident.log_activity(ActivityType.LLM_CALL, "diagnosis",
                                  "Requesting final diagnosis summary",
                                  metadata={"effort": "high", "reason": "max_loops_reached"})

            summary_prompt = _build_diagnosis_summary_prompt(incident, tool_results, is_audit)
            response = await self._llm.analyze(summary_prompt, effort="high")
            self._track_cost(response)

            text = response.get("text", "")
            diagnosis = DiagnosisResult.parse_from_text(text) if text else DiagnosisResult(
                root_cause="Unable to determine root cause",
                recommended_fix="Manual investigation required",
            )
            incident.root_cause = diagnosis.root_cause
            incident.state = IncidentState.REMEDIATION
            incident.log_activity(ActivityType.DECISION, "diagnosis",
                                  "Root cause identified (from summary)",
                                  detail=diagnosis.root_cause)
            incident.log_activity(ActivityType.PHASE_COMPLETE, "diagnosis", "Diagnosis complete")
            incident.current_agent_action = None
            logger.info(f"Diagnosis (summary) for {incident.id}: {diagnosis.root_cause[:150]}")

            return {
                **state,
                "incident": incident,
                "diagnosis": diagnosis.model_dump(),
                "tool_results": tool_results,
            }
        except Exception as e:
            logger.error(f"Diagnosis error for {incident.id}: {e}")
            incident.log_activity(ActivityType.ERROR, "diagnosis", f"Diagnosis failed: {e}")
            incident.state = IncidentState.ESCALATED
            incident.current_agent_action = None
            return {**state, "incident": incident, "error": str(e)}

    async def _remediation_node(self, state: IncidentGraphState) -> IncidentGraphState:
        """Phase 3: Apply or propose fix (medium effort)."""
        incident = state["incident"]
        incident.state = IncidentState.REMEDIATION
        incident.current_agent_action = "Preparing remediation plan..."
        incident.log_activity(ActivityType.PHASE_START, "remediation", "Remediation phase started",
                              detail=f"Root cause: {incident.root_cause or 'N/A'}")
        is_audit = self._config.security.mode == SentryMode.AUDIT

        try:
            prompt = _build_remediation_prompt(incident, is_audit)
            tools_used = []

            if is_audit:
                incident.current_agent_action = "Generating fix proposal (AUDIT mode)..."
                incident.log_activity(ActivityType.LLM_CALL, "remediation",
                                      "Requesting fix proposal (AUDIT — no execution)",
                                      metadata={"effort": "medium", "audit": True})
                response = await self._llm.analyze(prompt, effort="medium")
                self._track_cost(response)
                text = response.get("text", "")
                remediation = RemediationResult.parse_from_text(text)
                incident.fix_applied = f"[AUDIT] {remediation.fix_description}"
                incident.log_activity(ActivityType.DECISION, "remediation",
                                      "Fix proposed (AUDIT — not executed)",
                                      detail=remediation.fix_description)
            else:
                incident.current_agent_action = "Applying fix..."
                incident.log_activity(ActivityType.LLM_CALL, "remediation",
                                      "Requesting fix with tool access",
                                      metadata={"effort": "medium"})
                tools = self._tools.get_tool_definitions()
                response = await self._llm.analyze(prompt, effort="medium", tools=tools)
                self._track_cost(response)
                for tc in response.get("tool_calls", []):
                    args_summary = ", ".join(f"{k}={str(v)[:40]}" for k, v in tc.get("arguments", {}).items())
                    incident.log_activity(ActivityType.TOOL_CALL, "remediation",
                                          f"Applying: {tc['name']}",
                                          detail=args_summary,
                                          metadata={"tool": tc["name"]})
                    call = ToolCall(tool_name=tc["name"], arguments=tc.get("arguments", {}))
                    result = await self._tools.execute(call)
                    tools_used.append(tc["name"])
                    incident.log_activity(ActivityType.TOOL_RESULT, "remediation",
                                          f"{tc['name']} → {'✓' if result.success else '✗'}",
                                          detail=(result.output or result.error or "")[:300],
                                          metadata={"success": result.success})
                    if result.success:
                        incident.fix_applied = f"{tc['name']}: {result.output[:200]}"
                text = response.get("text", "")
                remediation = RemediationResult.parse_from_text(text, tools_used)
                if not incident.fix_applied:
                    incident.fix_applied = remediation.fix_description
                incident.log_activity(ActivityType.DECISION, "remediation",
                                      "Fix applied" if tools_used else "Fix described",
                                      detail=incident.fix_applied or "No fix",
                                      metadata={"tools_used": tools_used})

            incident.state = IncidentState.VERIFICATION
            incident.log_activity(ActivityType.PHASE_COMPLETE, "remediation", "Remediation complete")
            incident.current_agent_action = None
            logger.info(f"Remediation for {incident.id}: {incident.fix_applied[:150] if incident.fix_applied else 'none'}")

            return {
                **state,
                "incident": incident,
                "remediation": remediation.model_dump(),
            }
        except Exception as e:
            logger.error(f"Remediation error for {incident.id}: {e}")
            incident.log_activity(ActivityType.ERROR, "remediation", f"Remediation failed: {e}")
            incident.state = IncidentState.ESCALATED
            incident.current_agent_action = None
            return {**state, "incident": incident, "error": str(e)}

    async def _verification_node(self, state: IncidentGraphState) -> IncidentGraphState:
        """Phase 4: Verify the fix (disabled thinking for determinism)."""
        incident = state["incident"]
        incident.state = IncidentState.VERIFICATION
        incident.current_agent_action = "Verifying fix..."
        incident.log_activity(ActivityType.PHASE_START, "verification", "Verification phase started",
                              detail=f"Checking if fix resolved the issue")
        is_audit = self._config.security.mode == SentryMode.AUDIT

        try:
            incident.log_activity(ActivityType.LLM_CALL, "verification",
                                  "Calling LLM for verification (deterministic)",
                                  metadata={"effort": "disabled"})
            prompt = _build_verify_prompt(incident, is_audit)
            response = await self._llm.analyze(prompt, effort="disabled")
            self._track_cost(response)

            text = response.get("text", "")
            verification = VerificationResult.parse_from_text(text)

            if verification.resolved:
                incident.state = IncidentState.RESOLVED
                from datetime import datetime, timezone
                incident.resolved_at = datetime.now(timezone.utc)
                incident.log_activity(ActivityType.DECISION, "verification",
                                      "✅ Incident RESOLVED",
                                      detail=verification.reason)
            else:
                incident.retry_count += 1
                if incident.retry_count >= self._config.security.max_retries:
                    incident.state = IncidentState.ESCALATED
                    incident.log_activity(ActivityType.DECISION, "verification",
                                          "🚨 Max retries reached — ESCALATED",
                                          detail=f"Retries: {incident.retry_count}",
                                          metadata={"retry_count": incident.retry_count})
                else:
                    incident.state = IncidentState.DIAGNOSIS
                    incident.log_activity(ActivityType.DECISION, "verification",
                                          f"Fix not verified — retrying (attempt {incident.retry_count})",
                                          detail=verification.reason,
                                          metadata={"retry_count": incident.retry_count})

            incident.log_activity(ActivityType.PHASE_COMPLETE, "verification", "Verification complete",
                                  metadata={"resolved": verification.resolved})
            incident.current_agent_action = None
            logger.info(
                f"Verification for {incident.id}: "
                f"resolved={verification.resolved}, state={incident.state.value}"
            )
            return {
                **state,
                "incident": incident,
                "verification": verification.model_dump(),
            }
        except Exception as e:
            logger.error(f"Verification error for {incident.id}: {e}")
            incident.log_activity(ActivityType.ERROR, "verification", f"Verification failed: {e}")
            incident.state = IncidentState.ESCALATED
            incident.current_agent_action = None
            return {**state, "incident": incident, "error": str(e)}

    # ── Routing functions ────────────────────────────────

    def _route_after_triage(self, state: IncidentGraphState) -> Literal["diagnosis", "end"]:
        """Route after triage: investigate or ignore."""
        incident = state["incident"]
        if incident.state == IncidentState.IDLE or incident.state == IncidentState.ESCALATED:
            return "end"
        return "diagnosis"

    def _route_after_verification(self, state: IncidentGraphState) -> Literal["end", "diagnosis"]:
        """Route after verification: done or retry diagnosis."""
        incident = state["incident"]
        if incident.state in (IncidentState.RESOLVED, IncidentState.ESCALATED):
            return "end"
        return "diagnosis"

    # ── Helpers ──────────────────────────────────────────

    def _track_cost(self, response: dict) -> None:
        self._cb.record_usage(
            response.get("input_tokens", 0),
            response.get("output_tokens", 0),
        )
