"""
LangGraph-based state machine for incident resolution.
Replaces the manual state machine with a proper graph-based orchestration flow.

Uses LangGraph's StateGraph for ordered, deterministic state transitions:
  TRIAGE -> DIAGNOSIS -> REMEDIATION -> VERIFICATION -> RESOLVED/ESCALATED
"""

import logging
import os
from datetime import UTC
from typing import TYPE_CHECKING, Any, Literal, TypedDict, cast

from langgraph.graph import END, StateGraph

from backend.agents.detective_agent import DetectiveAgent
from backend.agents.surgeon_agent import SurgeonAgent

# Agent imports for Zero Trust delegation
from backend.agents.triage_agent import TriageAgent
from backend.agents.validator_agent import ValidatorAgent
from backend.shared.agent_throttle import AgentThrottle
from backend.shared.ai_gateway import AIGateway
from backend.shared.audit_log import ImmutableAuditLog
from backend.shared.circuit_breaker import CostCircuitBreaker
from backend.shared.config import AppConfig
from backend.shared.interfaces import ILLMClient, IMemoryStore, IToolExecutor
from backend.shared.models import (
    ActivityType,
    Incident,
    IncidentSeverity,
    IncidentState,
)
from backend.shared.tool_registry import TrustedToolRegistry
from backend.shared.vault import IVault

if TYPE_CHECKING:
    from langgraph.graph.state import CompiledStateGraph

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Graph State: typed dict that flows through every node
# ---------------------------------------------------------------------------

class IncidentGraphState(TypedDict, total=False):
    """State that flows through the LangGraph nodes."""
    incident: Incident
    service_context: str  # Rich service awareness context injected from ServiceRegistry
    triage: dict[str, Any]          # TriageResult as dict
    diagnosis: dict[str, Any]       # DiagnosisResult as dict
    remediation: dict[str, Any]     # RemediationResult as dict
    verification: dict[str, Any]    # VerificationResult as dict
    tool_results: list[str]         # Accumulated tool call results
    tool_loop_count: int  # How many diagnosis tool loops we've done
    error: str            # Error message if any node fails


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
        vault: IVault | None = None,
        gateway: AIGateway | None = None,
        audit_log: ImmutableAuditLog | None = None,
        throttle: AgentThrottle | None = None,
        registry: TrustedToolRegistry | None = None,
    ) -> None:
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

    def build(self) -> "CompiledStateGraph[Any, Any, Any, Any]":
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
            # ``vault`` / ``gateway`` are typed ``Optional[...]`` on the
            # builder because unit-test fixtures instantiate it with
            # ``None``; in production they are always wired. Cast so
            # strict mypy accepts the non-Optional agent signature.
            incident.current_agent_action = "Calling TriageAgent (secured)..."
            agent = TriageAgent(
                vault=cast(IVault, self._vault),
                llm=self._llm,
                gateway=cast(AIGateway, self._gateway),
                audit_log=self._audit_log,
            )
            result = await agent.run(incident, memory_hints=memory_hints, service_context=service_context)
            self._track_cost(result)
            self._apply_agent_activities(incident, result, "triage")

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
        """Phase 2: Deep analysis with tool loop (high effort).

        Delegates to DetectiveAgent which provides:
        - NHI identity + JIT credentials
        - Tool registry role-based ACL (read-only tools only)
        - Per-agent throttle (max actions/minute)
        - AI Gateway prompt injection + PII scanning
        - Immutable audit trail
        """
        incident = state["incident"]
        incident.state = IncidentState.DIAGNOSIS
        incident.current_agent_action = "Starting deep analysis..."
        incident.log_activity(ActivityType.PHASE_START, "diagnosis", "Diagnosis phase started",
                              detail="Deep root-cause analysis using high-effort reasoning with tool access")

        try:
            # Circuit breaker check stays in graph (orchestration logic)
            if self._cb.is_tripped:
                incident.log_activity(ActivityType.ERROR, "diagnosis", "Circuit breaker tripped — aborting")
                incident.state = IncidentState.ESCALATED
                incident.current_agent_action = None
                return {**state, "incident": incident, "error": "circuit_breaker_tripped"}

            service_context = state.get("service_context", "")

            # ── Delegate to DetectiveAgent (Zero Trust secured) ──
            # See TriageAgent instantiation for the ``cast(...)`` rationale.
            incident.current_agent_action = "Calling DetectiveAgent (secured)..."
            agent = DetectiveAgent(
                vault=cast(IVault, self._vault),
                llm=self._llm,
                tools=self._tools,
                registry=cast(TrustedToolRegistry, self._registry),
                gateway=cast(AIGateway, self._gateway),
                throttle=cast(AgentThrottle, self._throttle),
                audit_log=self._audit_log,
            )
            result = await agent.run(incident, service_context=service_context)
            self._track_cost(result)
            self._apply_agent_activities(incident, result, "diagnosis")

            # Apply result to incident
            incident.root_cause = result.get("root_cause", "Unknown")
            tool_results = result.get("tool_results", [])
            tool_result_summaries = []
            for tr in tool_results:
                if isinstance(tr, dict):
                    tool_result_summaries.append(f"{tr.get('tool','?')}: {tr.get('output','')[:200]}")
                else:
                    tool_result_summaries.append(str(tr)[:200])

            incident.state = IncidentState.REMEDIATION
            incident.log_activity(ActivityType.DECISION, "diagnosis",
                                  "Root cause identified",
                                  detail=incident.root_cause,
                                  metadata={"recommended_fix": result.get("recommended_fix", "")})
            incident.log_activity(ActivityType.PHASE_COMPLETE, "diagnosis", "Diagnosis complete")
            incident.current_agent_action = None
            logger.info(f"Diagnosis for {incident.id}: {incident.root_cause[:150]}")

            return {
                **state,
                "incident": incident,
                "diagnosis": result,
                "tool_results": tool_result_summaries,
            }
        except Exception as e:
            logger.error(f"Diagnosis error for {incident.id}: {e}")
            incident.log_activity(ActivityType.ERROR, "diagnosis", f"Diagnosis failed: {e}")
            incident.state = IncidentState.ESCALATED
            incident.current_agent_action = None
            return {**state, "incident": incident, "error": str(e)}

    async def _remediation_node(self, state: IncidentGraphState) -> IncidentGraphState:
        """Phase 3: Apply or propose fix (medium effort).

        Delegates to SurgeonAgent which provides:
        - NHI identity + JIT credentials
        - Tool registry role-based ACL (active tools: apply_patch, restart_service)
        - Per-agent throttle
        - AI Gateway scanning + audit trail
        """
        incident = state["incident"]
        incident.state = IncidentState.REMEDIATION
        incident.current_agent_action = "Preparing remediation plan..."
        incident.log_activity(ActivityType.PHASE_START, "remediation", "Remediation phase started",
                              detail=f"Root cause: {incident.root_cause or 'N/A'}")

        try:
            tool_results = state.get("tool_results", [])

            # ── Delegate to SurgeonAgent (Zero Trust secured) ──
            # See TriageAgent instantiation for the ``cast(...)`` rationale.
            incident.current_agent_action = "Calling SurgeonAgent (secured)..."
            agent = SurgeonAgent(
                vault=cast(IVault, self._vault),
                llm=self._llm,
                tools=self._tools,
                registry=cast(TrustedToolRegistry, self._registry),
                gateway=cast(AIGateway, self._gateway),
                throttle=cast(AgentThrottle, self._throttle),
                config=self._config,
                audit_log=self._audit_log,
            )
            result = await agent.run(incident, tool_results_context=tool_results)
            self._track_cost(result)
            self._apply_agent_activities(incident, result, "remediation")

            # Apply result to incident
            incident.fix_applied = result.get("fix_description", "No fix")
            tools_used = result.get("tools_used", [])

            # Git auto-commit stays in graph (orchestration logic, not agent logic)
            if "apply_patch" in tools_used:
                incident.current_agent_action = "Committing fix to git..."
                commit_hash = await self._auto_commit_fix(incident)
                if commit_hash:
                    incident.commit_id = commit_hash
                    incident.log_activity(ActivityType.INFO, "remediation",
                                          f"Fix committed to git: {commit_hash}",
                                          metadata={"commit_id": commit_hash})

            incident.state = IncidentState.VERIFICATION
            incident.log_activity(ActivityType.DECISION, "remediation",
                                  "Fix applied" if result.get("fix_applied") else "Fix proposed",
                                  detail=incident.fix_applied or "No fix",
                                  metadata={"tools_used": tools_used})
            incident.log_activity(ActivityType.PHASE_COMPLETE, "remediation", "Remediation complete")
            incident.current_agent_action = None
            logger.info(f"Remediation for {incident.id}: {incident.fix_applied[:150] if incident.fix_applied else 'none'}")

            return {
                **state,
                "incident": incident,
                "remediation": result,
            }
        except Exception as e:
            logger.error(f"Remediation error for {incident.id}: {e}")
            incident.log_activity(ActivityType.ERROR, "remediation", f"Remediation failed: {e}")
            incident.state = IncidentState.ESCALATED
            incident.current_agent_action = None
            return {**state, "incident": incident, "error": str(e)}

    async def _verification_node(self, state: IncidentGraphState) -> IncidentGraphState:
        """Phase 4: Verify the fix (disabled thinking for determinism).

        Delegates to ValidatorAgent which provides:
        - NHI identity + JIT credentials
        - AI Gateway scanning + audit trail
        """
        incident = state["incident"]
        incident.state = IncidentState.VERIFICATION
        incident.current_agent_action = "Verifying fix..."
        incident.log_activity(ActivityType.PHASE_START, "verification", "Verification phase started",
                              detail="Checking if fix resolved the issue")

        try:
            # ── Delegate to ValidatorAgent (Zero Trust secured) ──
            # See TriageAgent instantiation for the ``cast(...)`` rationale.
            incident.current_agent_action = "Calling ValidatorAgent (secured)..."
            agent = ValidatorAgent(
                vault=cast(IVault, self._vault),
                llm=self._llm,
                gateway=cast(AIGateway, self._gateway),
                audit_log=self._audit_log,
            )
            result = await agent.run(incident)
            self._track_cost(result)
            self._apply_agent_activities(incident, result, "verification")

            resolved = result.get("resolved", False)
            reason = result.get("reason", "")

            if resolved:
                incident.state = IncidentState.RESOLVED
                from datetime import datetime
                incident.resolved_at = datetime.now(UTC)
                incident.log_activity(ActivityType.DECISION, "verification",
                                      "✅ Incident RESOLVED",
                                      detail=reason)
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
                                          detail=reason,
                                          metadata={"retry_count": incident.retry_count})

            incident.log_activity(ActivityType.PHASE_COMPLETE, "verification", "Verification complete",
                                  metadata={"resolved": resolved})
            incident.current_agent_action = None
            logger.info(
                f"Verification for {incident.id}: "
                f"resolved={resolved}, state={incident.state.value}"
            )
            return {
                **state,
                "incident": incident,
                "verification": result,
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

    def _apply_agent_activities(
        self, incident: Incident, result: dict[str, Any], phase: str
    ) -> None:
        """Apply activity entries returned by an agent to the incident.

        Agents collect activities via BaseAgent._log_activity() during run().
        This method transfers them to the incident's activity log so the
        dashboard can display LLM_CALL, TOOL_CALL, TOOL_RESULT entries.
        """
        for activity in result.get("activities", []):
            try:
                activity_type = ActivityType(activity["activity_type"])
            except (ValueError, KeyError):
                activity_type = ActivityType.INFO
            incident.log_activity(
                activity_type,
                activity.get("agent", phase),
                activity.get("message", ""),
                detail=activity.get("detail", ""),
                metadata=activity.get("metadata"),
            )

    def _track_cost(self, response: dict[str, Any]) -> None:
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
        from git import Actor, InvalidGitRepositoryError, Repo
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
