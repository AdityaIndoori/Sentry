"""
LangGraph-based state machine for incident resolution.
Replaces the manual state machine with a proper graph-based orchestration flow.

Uses LangGraph's StateGraph for ordered, deterministic state transitions:
  TRIAGE -> DIAGNOSIS -> REMEDIATION -> VERIFICATION -> RESOLVED/ESCALATED
"""

import asyncio
import logging
import os
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

# Agent imports for Zero Trust delegation
from backend.agents.triage_agent import TriageAgent
from backend.agents.detective_agent import DetectiveAgent
from backend.agents.surgeon_agent import SurgeonAgent
from backend.agents.validator_agent import ValidatorAgent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Graph State: typed dict that flows through every node
# ---------------------------------------------------------------------------

class IncidentGraphState(TypedDict, total=False):
    """State that flows through the LangGraph nodes."""
    incident: Incident
    service_context: str  # Rich service awareness context injected from ServiceRegistry
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

def _build_triage_prompt(incident: Incident, history: list, service_context: str = "") -> str:
    hist_text = ""
    if history:
        hist_text = "\n\nSimilar past incidents:\n"
        for h in history[:3]:
            hist_text += f"- {h.symptom} -> {h.root_cause} -> Fix: {h.fix}\n"

    svc_text = ""
    if service_context:
        svc_text = f"\n\n--- SERVICE CONTEXT (what this error relates to) ---\n{service_context}\n--- END SERVICE CONTEXT ---\n"

    return (
        f"You are Sentry, an autonomous server monitoring AI.\n"
        f"Triage this production error log entry:\n\n"
        f"ERROR: {incident.symptom}\n"
        f"{svc_text}"
        f"{hist_text}\n"
        f"Respond in this EXACT format:\n"
        f"SEVERITY: <low|medium|high|critical>\n"
        f"VERDICT: <INVESTIGATE|FALSE POSITIVE>\n"
        f"SUMMARY: <one-line description of the issue>\n\n"
        f"IMPORTANT: Only use 'VERDICT: FALSE POSITIVE' for truly benign log entries. "
        f"Any actual error, exception, or service degradation MUST be 'VERDICT: INVESTIGATE'."
    )


def _build_diagnosis_prompt(incident: Incident, config: AppConfig, service_context: str = "") -> str:
    is_audit = config.security.mode == SentryMode.AUDIT
    audit_note = ""
    if is_audit:
        audit_note = (
            "\n\nIMPORTANT: System is in AUDIT mode. Active tools will only log intent. "
            "Read-only tools work normally. Focus on read-only investigation first, "
            "then provide your best diagnosis."
        )
    svc_text = ""
    if service_context:
        svc_text = (
            f"\n\n{service_context}\n"
            f"\nStart by reading the source code to understand how the service works. "
            f"Look at config files, entry points, error handlers, and dependencies. "
            f"Then investigate what went wrong."
        )
    return (
        f"You are diagnosing a server incident.\n"
        f"Symptom: {incident.symptom}\n"
        f"Severity: {incident.severity.value}\n"
        f"{svc_text}\n"
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


def _build_remediation_prompt(incident: Incident, is_audit: bool, tool_results: list = None) -> str:
    # Include code context from diagnosis so the Surgeon sees actual source code
    context = ""
    if tool_results:
        context = "\n\nCode investigated during diagnosis:\n"
        for r in tool_results[-15:]:
            context += f"  {r}\n"

    if is_audit:
        return (
            f"Root cause: {incident.root_cause}\n"
            f"Symptom: {incident.symptom}\n"
            f"{context}\n"
            f"System is in AUDIT mode. Describe the fix you WOULD apply. "
            f"Do NOT call any tools. Just describe the plan.\n"
            f"End with: FIX PROPOSED: <one-line summary>"
        )
    return (
        f"Root cause: {incident.root_cause}\n"
        f"Symptom: {incident.symptom}\n"
        f"{context}\n"
        f"Apply a fix using the available tools. Follow this workflow:\n"
        f"1. Use read_file to see the exact current code of the file(s) you need to patch.\n"
        f"2. Use apply_patch to make the minimal targeted fix.\n"
        f"3. CRITICAL: After patching, you MUST call restart_service (no arguments needed) "
        f"to restart the monitored service so the code changes take effect. "
        f"Without a restart, patched files won't be loaded by the running process.\n\n"
        f"Be conservative - prefer minimal, targeted patches. "
        f"Do NOT skip the restart_service step."
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
        vault=None,
        gateway=None,
        audit_log=None,
        throttle=None,
        registry=None,
    ):
        self._config = config
        self._llm = llm
        self._tools = tools
        self._memory = memory
        self._cb = circuit_breaker
        # Zero Trust dependencies — when present, nodes delegate to Agent classes
        self._vault = vault
        self._gateway = gateway
        self._audit_log = audit_log
        self._throttle = throttle
        self._registry = registry

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
        """Phase 1: Quick severity assessment (low effort).
        
        When Zero Trust deps are available, delegates to TriageAgent which provides:
        - NHI identity + JIT credentials
        - AI Gateway prompt injection scanning
        - AI Gateway PII redaction on outputs
        - Immutable audit trail logging
        """
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

            service_context = state.get("service_context", "")
            memory_hints = [{"symptom": h.symptom, "root_cause": h.root_cause} for h in relevant] if relevant else None

            # ── Delegate to TriageAgent (Zero Trust secured) ──
            incident.current_agent_action = "Calling TriageAgent (secured)..."
            agent = TriageAgent(
                vault=self._vault, llm=self._llm,
                gateway=self._gateway, audit_log=self._audit_log,
            )
            result = await agent.run(incident, memory_hints=memory_hints, service_context=service_context)
            self._track_cost(result)

            severity_str = result.get("severity", "medium")
            verdict = result.get("verdict", "INVESTIGATE")
            summary = result.get("summary", "")

            # ── Apply result to incident (shared path) ──
            logger.info(f"Triage for {incident.id}: severity={severity_str}, verdict={verdict}")
            sev_map = {
                "critical": IncidentSeverity.CRITICAL,
                "high": IncidentSeverity.HIGH,
                "medium": IncidentSeverity.MEDIUM,
                "low": IncidentSeverity.LOW,
            }
            incident.severity = sev_map.get(severity_str, IncidentSeverity.MEDIUM)
            incident.triage_result = summary

            if verdict == "FALSE_POSITIVE":
                incident.state = IncidentState.IDLE
                incident.log_activity(ActivityType.DECISION, "triage",
                                      "Classified as FALSE POSITIVE — ignoring",
                                      detail=summary)
            else:
                incident.state = IncidentState.DIAGNOSIS
                incident.log_activity(ActivityType.DECISION, "triage",
                                      f"Classified as {severity_str.upper()} — will investigate",
                                      detail=summary)

            incident.log_activity(ActivityType.PHASE_COMPLETE, "triage", "Triage complete",
                                  metadata={"severity": severity_str, "verdict": verdict})
            incident.current_agent_action = None

            return {
                **state,
                "incident": incident,
                "triage": {"severity": severity_str, "verdict": verdict, "summary": summary},
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
            # IMPORTANT: Diagnosis agent gets READ-ONLY tools only.
            # It must investigate and identify root cause but NEVER modify
            # system state. Only the Remediation agent gets apply_patch
            # and restart_service.
            tools = self._tools.get_read_only_tool_definitions()
            service_context = state.get("service_context", "")
            prompt = _build_diagnosis_prompt(incident, self._config, service_context)
            max_loops = self._config.security.max_retries

            for loop_idx in range(max_loops):
                if self._cb.is_tripped:
                    incident.log_activity(ActivityType.ERROR, "diagnosis", "Circuit breaker tripped — aborting")
                    incident.state = IncidentState.ESCALATED
                    incident.current_agent_action = None
                    return {**state, "incident": incident, "error": "circuit_breaker_tripped"}

                incident.current_agent_action = f"Calling LLM (effort: high, loop {loop_idx+1}/{max_loops})..."
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
                        # Bug fix #11: Truncate tool results appended to prompt to prevent
                        # unbounded growth. Each result is capped, and we cap total additions.
                        truncated_result = result_text[:2000]
                        prompt += f"\n\nTool {tc['name']} result: {truncated_result}"
                        tool_results.append(f"{tc['name']}: {result_text[:200]}")

                        # Cap total prompt size to prevent token explosion
                        if len(prompt) > 50000:
                            prompt = prompt[:25000] + "\n\n[... earlier context truncated ...]\n\n" + prompt[-20000:]

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
                    diagnosis = DiagnosisResult.parse_safe(text)
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
            diagnosis = DiagnosisResult.parse_safe(text) if text else DiagnosisResult(
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
            tool_results = state.get("tool_results", [])
            prompt = _build_remediation_prompt(incident, is_audit, tool_results=tool_results)
            tools_used = []

            if is_audit:
                incident.current_agent_action = "Generating fix proposal (AUDIT mode)..."
                incident.log_activity(ActivityType.LLM_CALL, "remediation",
                                      "Requesting fix proposal (AUDIT — no execution)",
                                      metadata={"effort": "medium", "audit": True})
                response = await self._llm.analyze(prompt, effort="medium")
                self._track_cost(response)
                text = response.get("text", "")
                remediation = RemediationResult.parse_safe(text)
                incident.fix_applied = f"[AUDIT] {remediation.fix_description}"
                incident.log_activity(ActivityType.DECISION, "remediation",
                                      "Fix proposed (AUDIT — not executed)",
                                      detail=remediation.fix_description)
            else:
                # Multi-step tool loop: Surgeon reads file, patches, restarts.
                # Only expose read_file + active tools to prevent the LLM from
                # wasting loops on grep_search/fetch_docs investigation.
                tools = self._tools.get_remediation_tool_definitions()
                max_remediation_loops = 4
                remediation_prompt = prompt

                for rem_loop in range(max_remediation_loops):
                    incident.current_agent_action = f"Applying fix (step {rem_loop+1}/{max_remediation_loops})..."
                    incident.log_activity(ActivityType.LLM_CALL, "remediation",
                                          f"Requesting fix with tool access (step {rem_loop+1})",
                                          metadata={"effort": "medium", "loop": rem_loop+1})

                    response = await self._llm.analyze(remediation_prompt, effort="medium", tools=tools)
                    self._track_cost(response)

                    tool_calls = response.get("tool_calls", [])
                    if not tool_calls:
                        # No more tool calls — LLM provided a text response
                        break

                    for tc in tool_calls:
                        args_summary = ", ".join(f"{k}={str(v)[:40]}" for k, v in tc.get("arguments", {}).items())
                        incident.log_activity(ActivityType.TOOL_CALL, "remediation",
                                              f"Applying: {tc['name']}",
                                              detail=args_summary,
                                              metadata={"tool": tc["name"]})
                        call = ToolCall(tool_name=tc["name"], arguments=tc.get("arguments", {}))
                        result = await self._tools.execute(call)
                        tools_used.append(tc["name"])
                        result_text = result.output or result.error or ""
                        # Feed tool results back into the prompt for the next loop
                        remediation_prompt += f"\n\nTool {tc['name']} result: {result_text[:2000]}"
                        incident.log_activity(ActivityType.TOOL_RESULT, "remediation",
                                              f"{tc['name']} → {'✓' if result.success else '✗'}",
                                              detail=result_text[:300],
                                              metadata={"success": result.success})
                        if result.success and tc["name"] == "apply_patch":
                            incident.fix_applied = f"{tc['name']}: {result_text[:200]}"
                        elif result.success and tc["name"] == "restart_service":
                            incident.fix_applied = f"{tc['name']}: {result_text[:200]}"

                    # Cap prompt size
                    if len(remediation_prompt) > 50000:
                        remediation_prompt = remediation_prompt[:25000] + "\n\n[...truncated...]\n\n" + remediation_prompt[-20000:]

                text = response.get("text", "")
                remediation = RemediationResult.parse_safe(text, tools_used)
                if not incident.fix_applied:
                    incident.fix_applied = remediation.fix_description
                incident.log_activity(ActivityType.DECISION, "remediation",
                                      "Fix applied" if any(t in tools_used for t in ("apply_patch", "restart_service")) else "Fix described",
                                      detail=incident.fix_applied or "No fix",
                                      metadata={"tools_used": tools_used, "loops": rem_loop + 1})

                # Auto-commit the fix to git if apply_patch was used
                if "apply_patch" in tools_used:
                    incident.current_agent_action = "Committing fix to git..."
                    commit_hash = await self._auto_commit_fix(incident)
                    if commit_hash:
                        incident.commit_id = commit_hash
                        incident.log_activity(ActivityType.INFO, "remediation",
                                              f"Fix committed to git: {commit_hash}",
                                              metadata={"commit_id": commit_hash})

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
            verification = VerificationResult.parse_safe(text)

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

    async def _auto_commit_fix(self, incident: Incident) -> str | None:  # pragma: no cover
        """
        Auto-commit the fix to the monitored service's git repo using GitPython.
        Returns the short commit hash, or None if the repo is not a git repo.
        Only commits if .git already exists — does NOT initialize new repos.
        """
        from git import Repo, InvalidGitRepositoryError, Actor
        project_root = self._config.security.project_root

        try:
            git_dir = os.path.join(project_root, ".git")
            if not os.path.isdir(git_dir):
                logger.info(f"Not a git repo ({project_root}) — skipping auto-commit")
                return None

            repo = Repo(project_root)

            # Stage all changes
            repo.git.add(A=True)

            # Check if there are staged changes to commit
            if not repo.index.diff("HEAD"):
                logger.info("No staged changes to commit")
                return None

            # Build commit message
            summary = (incident.root_cause or incident.symptom or "fix")[:72]
            summary = summary.replace("\n", " ")
            commit_msg = f"sentry-fix({incident.id}): {summary}"

            # Commit with Sentry Bot author
            author = Actor("Sentry Bot", "sentry@auto-heal")
            repo.index.commit(commit_msg, author=author, committer=author)

            commit_hash = repo.head.commit.hexsha[:8]
            logger.info(f"Auto-committed fix for {incident.id}: {commit_hash}")
            return commit_hash

        except InvalidGitRepositoryError:
            logger.info(f"Not a valid git repo ({project_root}) — skipping auto-commit")
            return None
        except Exception as e:
            logger.warning(f"Auto-commit failed: {e}")
            return None
