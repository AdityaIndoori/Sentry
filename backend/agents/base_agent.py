"""
Base Agent - Abstract base class for all agents.

Each agent:
1. Registers with the Vault to get a unique NHI
2. Requests JIT credentials before each operation
3. Has its I/O scanned by the AI Gateway
4. Logs all security-critical actions to the immutable audit trail
5. Sanitizes all inputs before processing
6. All LLM calls and tool executions are automatically activity-logged
   via _call_llm() and _call_tool() — the only way to access these resources
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

from backend.shared.vault import AgentRole, LocalVault, NonHumanIdentity, IVault
from backend.shared.ai_gateway import AIGateway
from backend.shared.audit_log import ImmutableAuditLog
from backend.shared.metrics import inc_llm_call, inc_tool_call, observe_llm_cost
from backend.shared.observability import get_telemetry
from backend.shared.models import ToolCall, ToolResult
from backend.shared.security import SecurityGuard

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class for all Sentry agents.
    
    LLM and tool executor are stored with name-mangling (__llm, __tools)
    so subclasses cannot access them directly. The only way to call the LLM
    or execute a tool is through _call_llm() and _call_tool(), which
    automatically log activity entries. This guarantees every LLM call and
    tool execution is activity-logged — no agent can bypass this.
    """

    def __init__(
        self,
        vault: IVault,
        role: AgentRole,
        gateway: AIGateway,
        audit_log: Optional[ImmutableAuditLog] = None,
        security: Optional[SecurityGuard] = None,
        llm: Any = None,
        tools: Any = None,
    ):
        self._vault = vault
        self._gateway = gateway
        self._audit_log = audit_log
        self._security = security
        self._role = role
        # Name-mangled: subclasses cannot access self.__llm or self.__tools
        # They MUST use self._call_llm() and self._call_tool() which auto-log
        self.__llm = llm
        self.__tools = tools
        # Activity log — collected during run(), returned to graph node
        self._activities: list[dict] = []
        self._call_count: int = 0
        # Register NHI
        self._nhi = vault.register_agent(role)
        logger.info(f"Agent registered: {self._nhi.agent_id} (role={role.value})")

    @property
    def nhi(self) -> NonHumanIdentity:
        """This agent's unique Non-Human Identity."""
        return self._nhi

    @property
    def agent_id(self) -> str:
        return self._nhi.agent_id

    # ── Activity logging (returned to graph node) ─────────

    def _log_activity(self, activity_type: str, message: str, detail: str = "",
                      metadata: Optional[dict] = None):
        """Record an activity entry. Graph node applies these to the incident after run()."""
        self._activities.append({
            "activity_type": activity_type,
            "agent": self._role.value,
            "message": message,
            "detail": detail or "",
            "metadata": metadata or {},
        })

    # ── LLM access (the ONLY way to call the LLM) ────────

    async def _call_llm(self, prompt: str, effort: str, tools: list = None) -> dict:
        """Call the LLM. Automatically logs LLM_CALL and INFO activities.

        This is the ONLY way to access the LLM from any agent.
        Direct access to self.__llm is blocked by name mangling.

        P4.1: mirrors the P1.4 tool-credential pattern — every LLM call
        requests a short-lived JIT credential from the vault scoped to
        ``llm_call`` and revokes it in ``finally`` regardless of outcome.
        The credential is stamped onto the OTel span so compromised
        traces can be correlated back to a specific issuance. LLM clients
        don't (yet) verify the credential; this still matters because:

          * runaway / compromised agent code can't call the LLM without
            presenting a valid, vault-issued, unrevoked credential ID —
            ``STOP_SENTRY`` / ``vault.revoke_all()`` drains in-flight
            calls the same way it drains tool calls;
          * future ``ILLMClient`` wrappers (e.g. the P2.2 secrets-backed
            client) can verify the credential to gate API-key access.
        """
        self._call_count += 1
        self._log_activity(
            "LLM_CALL",
            f"Calling LLM (effort: {effort}, call #{self._call_count})",
            metadata={"effort": effort, "call_number": self._call_count},
        )
        # P2.3b-full: Prometheus counter for every LLM call dispatched.
        try:
            inc_llm_call()
        except Exception:  # pragma: no cover
            logger.exception("metrics: inc_llm_call failed")

        # P4.1: issue a JIT credential for this LLM call. Scope is
        # ``llm_call`` with a 30-second TTL — longer than a single tool
        # call because big-model latency can exceed the 10-second default.
        # Revoked in ``finally`` so a malicious replay is blocked even if
        # the raw token leaks mid-flight.
        credential = None
        try:
            credential = self._vault.issue_credential(
                self.agent_id, scope="llm_call", ttl_seconds=30,
            )
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning(
                f"Vault failed to issue LLM credential for {self.agent_id}: {exc}"
            )

        # If the vault is wired and denied the request, abort cleanly with
        # an audit entry rather than silently bypassing zero-trust. When
        # the vault is NOT wired (unit tests) credential stays ``None`` and
        # we fall through to the legacy direct-call behaviour.
        if credential is None and self._vault is not None:
            # Distinguish "no vault configured" from "vault said no" —
            # LocalVault.issue_credential returns None only on failure
            # (unknown agent / revoked / kill-switch). Absence of a
            # vault backend means self._vault is None, handled above.
            self._audit(
                "llm_call_blocked",
                f"agent={self.agent_id} scope=llm_call",
                "denied",
            )
            raise PermissionError(
                f"Agent {self.agent_id} denied LLM credential "
                f"(STOP_SENTRY / revoke_all may be active)"
            )

        try:
            # P2.3b-full: open an OTel span scoped to the LLM round-trip.
            with get_telemetry().span(
                "agent.llm_call",
                agent=self._role.value,
                effort=effort,
                call_number=self._call_count,
                credential_id=(credential.credential_id if credential else ""),
            ):
                response = await self.__llm.analyze(
                    prompt=prompt, effort=effort, tools=tools,
                )
        finally:
            if credential is not None:
                try:
                    self._vault.revoke_credential(credential.credential_id)
                except Exception as exc:  # pragma: no cover — defensive
                    logger.warning(
                        f"Vault failed to revoke LLM credential "
                        f"{credential.credential_id}: {exc}"
                    )

        input_tokens = response.get("input_tokens", 0)
        output_tokens = response.get("output_tokens", 0)
        # Observe cost if the LLM client propagated a usd estimate; many
        # providers don't, in which case this is a no-op.
        try:
            cost_usd = response.get("cost_usd") or response.get("usage", {}).get("cost_usd", 0)
            if cost_usd:
                observe_llm_cost(float(cost_usd))
        except Exception:  # pragma: no cover
            logger.exception("metrics: observe_llm_cost failed")

        self._log_activity(
            "INFO",
            "LLM response received",
            detail=f"tokens: {input_tokens} in / {output_tokens} out",
            metadata={"input_tokens": input_tokens, "output_tokens": output_tokens},
        )
        return response

    # ── Tool access (the ONLY way to execute a tool) ──────

    async def _call_tool(self, tool_name: str, arguments: dict) -> ToolResult:
        """Execute a tool. Automatically logs TOOL_CALL and TOOL_RESULT activities.

        This is the ONLY way to execute a tool from any agent.
        Direct access to self.__tools is blocked by name mangling.

        P1.4: Before invoking the executor we request a short-lived JIT
        credential from the vault scoped specifically to ``tool:{tool_name}``,
        pass it to the executor, and revoke it immediately after the call
        completes (success OR failure). The ToolExecutor verifies the
        credential against the same vault before executing — a forged or
        replayed credential is hard-rejected at the tool boundary.
        """
        args_summary = ", ".join(f"{k}={str(v)[:50]}" for k, v in arguments.items())
        self._log_activity(
            "TOOL_CALL",
            f"Calling {tool_name}",
            detail=args_summary,
            metadata={"tool": tool_name, "args": {k: str(v)[:100] for k, v in arguments.items()}},
        )

        # Issue a JIT credential for this tool call (scope = "tool:<name>").
        # The credential has a 30-second TTL and is revoked in `finally`
        # regardless of success. If the vault is unavailable we still
        # proceed — this preserves behaviour for unit tests that construct
        # ToolExecutor without a vault. When a vault IS wired, the executor
        # will reject the call if no credential is presented.
        credential = None
        try:
            credential = self._vault.issue_credential(
                self.agent_id, scope=f"tool:{tool_name}", ttl_seconds=30,
            )
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning(
                f"Vault failed to issue credential for {self.agent_id} "
                f"scope=tool:{tool_name}: {exc}"
            )

        try:
            call = ToolCall(tool_name=tool_name, arguments=arguments)
            # P2.3b-full: OTel span for each tool execution.
            with get_telemetry().span(
                "agent.tool_call",
                agent=self._role.value,
                tool=tool_name,
            ):
                result = await self.__tools.execute(
                    call, caller_role=self._role, credential=credential,
                )
        finally:
            if credential is not None:
                try:
                    self._vault.revoke_credential(credential.credential_id)
                except Exception as exc:  # pragma: no cover — defensive
                    logger.warning(
                        f"Vault failed to revoke credential "
                        f"{credential.credential_id}: {exc}"
                    )

        result_text = result.output or result.error or ""
        self._log_activity(
            "TOOL_RESULT",
            f"{tool_name} → {'✓' if result.success else '✗'}",
            detail=result_text[:300],
            metadata={"success": result.success, "audit_only": getattr(result, 'audit_only', False)},
        )
        # P2.3b-full: Prometheus counter for tool outcomes.
        try:
            inc_tool_call(tool_name, bool(result.success))
        except Exception:  # pragma: no cover
            logger.exception("metrics: inc_tool_call failed")
        return result

    def _get_tool_definitions(self, category: str = "all") -> list:
        """Get tool definitions for LLM tool_use parameter. No logging needed."""
        if self.__tools is None:
            return []
        if category == "read_only" and hasattr(self.__tools, 'get_read_only_tool_definitions'):
            return self.__tools.get_read_only_tool_definitions()
        if category == "remediation" and hasattr(self.__tools, 'get_remediation_tool_definitions'):
            return self.__tools.get_remediation_tool_definitions()
        if hasattr(self.__tools, 'get_tool_definitions'):
            return self.__tools.get_tool_definitions()
        return []

    # ── Audit trail (security events) ─────────────────────

    def _audit(self, action: str, detail: str, result: str = "", metadata: Optional[dict] = None):
        """Log an action to the immutable audit trail (if configured)."""
        if self._audit_log:
            self._audit_log.log_action(
                agent_id=self.agent_id,
                action=action,
                detail=detail,
                result=result,
                metadata=metadata,
            )

    # ── Credential management ─────────────────────────────

    def _get_credential(self, scope: str, ttl: int = 60):
        """Request a JIT credential from the vault."""
        cred = self._vault.issue_credential(self.agent_id, scope=scope, ttl_seconds=ttl)
        if not cred:
            self._audit("credential_denied", f"scope={scope}", "denied")
            raise PermissionError(
                f"Agent {self.agent_id} denied credential for scope={scope}"
            )
        self._audit(
            "credential_issued",
            f"scope={scope}, ttl={ttl}s",
            f"credential_id={cred.credential_id}",
        )
        return cred

    # ── Input/Output scanning ─────────────────────────────

    def _scan_input(self, text: str) -> str:
        """Sanitize input, then scan through AI Gateway. Raises if unsafe."""
        if self._security:
            sanitized = self._security.sanitize_input(text)
        else:
            dangerous = [";", "&&", "||", "|", "`", "$(", ">>", "<<"]
            sanitized = text
            for char in dangerous:
                sanitized = sanitized.replace(char, "")
            sanitized = sanitized.strip()

        result = self._gateway.scan_input(sanitized)
        if not result.is_safe:
            logger.warning(
                f"BLOCKED INPUT for {self.agent_id}: threats={result.threats}"
            )
            self._audit(
                "input_blocked",
                f"threats={result.threats}",
                "blocked",
                metadata={"threats": result.threats},
            )
            raise ValueError(
                f"Input blocked by AI Gateway: {result.threats}"
            )
        return sanitized

    def _scan_and_redact_output(self, text: str) -> str:
        """Scan and redact output through AI Gateway."""
        scan = self._gateway.scan_output(text)
        if not scan.is_safe:
            logger.warning(
                f"PII detected in output for {self.agent_id}: {scan.threats}"
            )
            self._audit(
                "pii_detected",
                f"threats={scan.threats}",
                "redacted",
                metadata={"threats": scan.threats},
            )
            return self._gateway.redact_output(text)
        return text
