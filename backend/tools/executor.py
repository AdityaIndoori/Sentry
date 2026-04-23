"""
Tool executor - routes tool calls to appropriate handlers.
Implements IToolExecutor interface (Dependency Inversion).

Production hardening:
- #3: Pydantic arg validation before execution (single source of truth)
- #4: Empty-output rejection — success=True requires non-empty output
- #5: Transient failure retry with backoff for tool execution
"""

import asyncio
import logging
from typing import Any

from pydantic import ValidationError

from backend.shared.audit_log import ImmutableAuditLog
from backend.shared.circuit_breaker import RateLimiter
from backend.shared.config import SentryMode
from backend.shared.interfaces import IToolExecutor
from backend.shared.models import ToolCall, ToolCategory, ToolResult
from backend.shared.security import SecurityGuard
from backend.shared.tool_registry import TrustedToolRegistry
from backend.shared.vault import AgentRole, IVault, JITCredential

from .active_tools import RunDiagnosticsTool
from .patch_tool import ApplyPatchTool
from .read_only_tools import FetchDocsTool, GrepSearchTool, ReadFileTool
from .restart_tool import RestartServiceTool
from .tool_schemas import TOOL_ARG_MODELS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool retry constants (#5)
# ---------------------------------------------------------------------------
TOOL_MAX_RETRIES = 2           # 1 initial + 1 retry
TOOL_BACKOFF_SECONDS = 1.0     # Short backoff for tool retries
TOOL_TIMEOUT_SECONDS = 60      # Max time for a single tool execution

_TOOL_TRANSIENT_KEYWORDS = (
    "timeout", "timed out", "connection", "reset",
    "broken pipe", "eof", "temporarily", "503", "502",
)


def _is_tool_transient(error_str: str) -> bool:
    """Check if a tool error is transient and worth retrying."""
    lower = error_str.lower()
    return any(kw in lower for kw in _TOOL_TRANSIENT_KEYWORDS)


class ToolExecutor(IToolExecutor):
    """Routes tool calls to implementations with security checks.

    Defense-in-depth: If a TrustedToolRegistry is provided, the executor
    enforces role-based tool ACL at execution time. This is a safety net —
    even if an agent bypasses its own registry check, the executor blocks
    unauthorized tool access.
    """

    def __init__(self, security: SecurityGuard, project_root: str,
                 audit_log: ImmutableAuditLog | None = None,
                 registry: TrustedToolRegistry | None = None,
                 vault: IVault | None = None):
        self._security = security
        self._audit_log = audit_log
        self._registry = registry
        self._vault = vault
        self._rate_limiter = RateLimiter()

        # Initialize tools
        self._read_file = ReadFileTool(security, project_root)
        self._grep = GrepSearchTool(security, project_root)
        self._fetch = FetchDocsTool(security)
        self._diagnostics = RunDiagnosticsTool(security)
        self._patch = ApplyPatchTool(security, project_root)
        self._restart = RestartServiceTool(
            security, self._rate_limiter,
            security._config.restart_cooldown_seconds,
        )

        # ``Any`` here is intentional: the six tool classes have divergent
        # ``execute(...)`` signatures and a common ``definition()``
        # staticmethod, but no shared ABC. Narrowing this to a ``Protocol``
        # would force every tool to declare its full ``execute`` kwargs on
        # the protocol, which is out-of-scope for this annotation pass.
        self._tool_map: dict[str, tuple[Any, ToolCategory]] = {
            "read_file": (self._read_file, ToolCategory.READ_ONLY),
            "grep_search": (self._grep, ToolCategory.READ_ONLY),
            "fetch_docs": (self._fetch, ToolCategory.READ_ONLY),
            "run_diagnostics": (self._diagnostics, ToolCategory.ACTIVE),
            "apply_patch": (self._patch, ToolCategory.ACTIVE),
            "restart_service": (self._restart, ToolCategory.ACTIVE),
        }


    def _audit(
        self,
        action: str,
        detail: str,
        result: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log to immutable audit trail if configured."""
        if self._audit_log:
            self._audit_log.log_action(
                agent_id="tool_executor",
                action=action,
                detail=detail,
                result=result,
                metadata=metadata,
            )

    def _validate_tool_content(
        self, tool_name: str, args: dict[str, Any]
    ) -> str | None:
        """P0.1b: Enforce tool-specific content rules BEFORE AUDIT short-circuit.

        Returns an error string if validation fails, or None if OK. These are
        the same checks each tool runs internally — duplicating them here
        ensures that the outer AUDIT short-circuit never lets malicious args
        through as "audit_only=True".

        The individual tools still validate themselves when actually executed,
        so this is defense-in-depth rather than a new gate.
        """
        sg = self._security
        if tool_name == "run_diagnostics":
            cmd = args.get("command", "")
            # sanitize happened earlier; validate_command reads the first token
            sanitized = sg.sanitize_input(cmd)
            if not sg.validate_command(sanitized):
                return f"Command not in whitelist: {sanitized}"
            return None

        if tool_name in ("read_file", "grep_search"):
            path = args.get("path", "")
            if tool_name == "grep_search" and not path:
                path = "."
            # Note: sanitize_input strips some characters but validate_path
            # is what enforces the traversal / escape rules.
            sanitized_path = sg.sanitize_input(path)
            if not sg.validate_path(sanitized_path):
                return "Path validation failed"
            return None

        if tool_name == "apply_patch":
            # Only the path is a security-critical argument here; the diff
            # itself is validated semantically by the patch engine.
            path = args.get("file_path", "")
            sanitized_path = sg.sanitize_input(path)
            if not sg.validate_path(sanitized_path):
                return "Path validation failed"
            return None

        if tool_name == "fetch_docs":
            url = args.get("url", "")
            if not sg.validate_url(url):
                return "URL not in allow-list"
            return None

        # restart_service: no user-supplied args to validate (the command
        # comes from SERVICE_RESTART_CMD env var and is trusted by the
        # operator).
        return None

    async def execute(
        self,
        tool_call: ToolCall,
        caller_role: AgentRole | None = None,
        credential: JITCredential | None = None,
    ) -> ToolResult:
        # --- P1.4: Zero-Trust JIT credential enforcement ---
        #
        # When a vault is wired, every tool invocation must present a valid
        # JIT credential that was issued BY THE SAME VAULT for this agent
        # and scope. This turns the credential plumbing from ornamental
        # into mandatory: a forged or replayed credential is rejected at
        # the executor boundary.
        #
        # The check is gated on ``self._vault is not None`` so legacy
        # constructions (``ToolExecutor(security, project_root)`` in
        # unit tests) continue to work without credentials.
        if self._vault is not None:
            expected_scope = f"tool:{tool_call.tool_name}"
            agent_id_for_verify = (
                credential.agent_id if credential is not None else None
            )
            credential_id_for_verify = (
                credential.credential_id if credential is not None else None
            )

            # No credential presented at all.
            if credential is None:
                logger.warning(
                    f"[VAULT] Tool '{tool_call.tool_name}' invoked without a "
                    f"JIT credential — rejecting."
                )
                self._audit(
                    "tool_blocked",
                    f"tool={tool_call.tool_name}",
                    "no_credential",
                    metadata={
                        "tool": tool_call.tool_name,
                        "reason": "missing_credential",
                    },
                )
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error="JIT credential required for tool execution.",
                )

            # Credential presented — verify with the vault.
            # mypy: after the ``credential is None: return`` guard above,
            # ``credential`` is narrowed to ``JITCredential``; re-read the
            # fields so mypy sees ``str`` instead of ``str | None``.
            credential_id_for_verify = credential.credential_id
            agent_id_for_verify = credential.agent_id
            if not self._vault.verify_credential(
                credential_id_for_verify,
                agent_id_for_verify,
                expected_scope,
            ):

                logger.warning(
                    f"[VAULT] Credential verification failed for tool "
                    f"'{tool_call.tool_name}' "
                    f"(cred_id={credential_id_for_verify}, "
                    f"agent={agent_id_for_verify}, scope={expected_scope})"
                )
                self._audit(
                    "cred_verify_failed",
                    f"tool={tool_call.tool_name}, agent={agent_id_for_verify}",
                    "rejected",
                    metadata={
                        "tool": tool_call.tool_name,
                        "agent_id": agent_id_for_verify,
                        "credential_id": credential_id_for_verify,
                        "reason": "credential_rejected",
                    },
                )
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error="JIT credential rejected by vault.",
                )

        # --- Sanitize all string arguments before processing ---
        sanitized_args = {}
        for key, val in (tool_call.arguments or {}).items():
            if isinstance(val, str):
                sanitized_args[key] = self._security.sanitize_input(val)
            else:
                sanitized_args[key] = val
        tool_call = ToolCall(tool_name=tool_call.tool_name, arguments=sanitized_args)

        if self._security.is_stopped():
            self._audit(
                "tool_blocked",
                f"tool={tool_call.tool_name}",
                "STOP_SENTRY active",
                metadata={"tool": tool_call.tool_name, "reason": "stop_file"},
            )
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error="STOP_SENTRY is active. All operations halted.",
            )

        # Bug fix #14: DISABLED mode should block ALL tool execution
        if self._security.mode == SentryMode.DISABLED:
            self._audit(
                "tool_blocked",
                f"tool={tool_call.tool_name}",
                "DISABLED mode",
                metadata={"tool": tool_call.tool_name, "reason": "disabled_mode"},
            )
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error="System is in DISABLED mode. No tools can execute.",
            )

        entry = self._tool_map.get(tool_call.tool_name)
        if not entry:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=f"Unknown tool: {tool_call.tool_name}",
            )

        tool, category = entry

        # Defense-in-depth: Tool Registry role-based ACL check.
        # If a registry and caller_role are provided, verify the tool is
        # in the caller's allowlist. This catches cases where an agent
        # somehow bypasses its own registry check (e.g., future agent
        # that doesn't use BaseAgent._call_tool).
        if self._registry and caller_role:
            if not self._registry.is_allowed(tool_call.tool_name, caller_role):
                logger.warning(
                    f"[REGISTRY] Blocked tool '{tool_call.tool_name}' for role "
                    f"'{caller_role.value}' at executor level"
                )
                self._audit(
                    "tool_blocked",
                    f"tool={tool_call.tool_name}, role={caller_role.value}",
                    "registry_denied",
                    metadata={
                        "tool": tool_call.tool_name,
                        "role": caller_role.value,
                        "reason": "registry_acl",
                    },
                )
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error=f"Tool '{tool_call.tool_name}' not allowed for role '{caller_role.value}'",
                )

        # --- #3: Pydantic arg validation (single source of truth) ---
        # P0.1b: Pydantic validation MUST run before the AUDIT short-circuit
        # below. Otherwise an attacker can submit malformed args in AUDIT
        # mode and have them silently "logged and not executed" — but the
        # audit log records a sanitized version rather than hard-rejecting.
        arg_model = TOOL_ARG_MODELS.get(tool_call.tool_name)
        if arg_model:
            try:
                validated = arg_model.model_validate(tool_call.arguments)
                # Use validated (coerced) args going forward
                validated_args = validated.model_dump()
            except ValidationError as e:
                logger.warning(
                    f"Arg validation failed for {tool_call.tool_name}: {e}"
                )
                self._audit(
                    "tool_blocked",
                    f"tool={tool_call.tool_name}",
                    "invalid_arguments",
                    metadata={"tool": tool_call.tool_name, "reason": "pydantic_validation"},
                )
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error=f"Invalid arguments: {e}",
                )
        else:
            validated_args = tool_call.arguments

        # --- P0.1b: Tool-specific content validation BEFORE AUDIT short-circuit ---
        # The outer AUDIT short-circuit historically returned audit_only=True
        # for any ACTIVE tool call, skipping the tool's own validators
        # (validate_command, validate_path, validate_url). That meant a
        # malicious command like `rm -rf /` passed in AUDIT mode was recorded
        # as "safely logged" when it should have been hard-rejected.
        #
        # We run the same content validators that each tool runs internally,
        # but do it here BEFORE the AUDIT short-circuit so that garbage input
        # is always rejected regardless of mode. This is defense-in-depth:
        # the tools still validate themselves when actually executed, and the
        # executor validates one layer out.
        content_error = self._validate_tool_content(tool_call.tool_name, validated_args)
        if content_error is not None:
            logger.warning(
                f"Content validation failed for {tool_call.tool_name}: {content_error}"
            )
            self._audit(
                "tool_blocked",
                f"tool={tool_call.tool_name}",
                "content_validation",
                metadata={"tool": tool_call.tool_name, "reason": "content_validation"},
            )
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=content_error,
            )

        # Bug fix #10: Enforce audit mode centrally for ACTIVE tools.
        # Individual tools check audit mode themselves, but this provides
        # a safety net at the executor level for any tool that forgets.
        #
        # P0.1b: This short-circuit NOW runs AFTER both Pydantic and
        # content validation so malicious args cannot slip through as
        # "audit_only=True".
        if category == ToolCategory.ACTIVE and self._security.is_audit_mode():
            logger.info(
                f"[AUDIT] Blocked active tool at executor level: "
                f"{tool_call.tool_name}"
            )
            self._audit(
                "tool_blocked",
                f"tool={tool_call.tool_name}",
                "AUDIT mode",
                metadata={"tool": tool_call.tool_name, "reason": "audit_mode"},
            )
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                output=f"[AUDIT MODE] Tool {tool_call.tool_name} logged but not executed.",
                audit_only=True,
            )

        logger.info(
            f"Executing tool: {tool_call.tool_name} "
            f"(category={category.value})"
        )

        # --- #5: Tool retry on transient failures ---
        last_error = None
        for attempt in range(1, TOOL_MAX_RETRIES + 1):
            try:
                raw = await asyncio.wait_for(
                    tool.execute(**validated_args),
                    timeout=TOOL_TIMEOUT_SECONDS,
                )
                success = raw.get("success", False)
                output = raw.get("output", "")
                error = raw.get("error")
                audit_only = raw.get("audit_only", False)

                # --- #4: Empty-output rejection ---
                # A "success" with no output is suspicious; demote to failure
                # (except audit-only results which legitimately have short output)
                if success and not output and not audit_only:
                    logger.warning(
                        f"Tool {tool_call.tool_name} returned success but "
                        f"empty output — demoting to failure"
                    )
                    success = False
                    error = error or "Tool returned success but produced no output"

                self._audit(
                    "tool_execution",
                    f"tool={tool_call.tool_name}, category={category.value}",
                    f"success={success}",
                    metadata={"tool": tool_call.tool_name, "success": success, "category": category.value},
                )
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=success,
                    output=output,
                    error=error,
                    audit_only=audit_only,
                )
            except TimeoutError:
                last_error = f"Tool {tool_call.tool_name} timed out after {TOOL_TIMEOUT_SECONDS}s"
                logger.warning(f"{last_error} (attempt {attempt}/{TOOL_MAX_RETRIES})")
            except TypeError as e:
                # Permanent: bad arguments won't fix on retry
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error=f"Invalid arguments: {e}",
                )
            except Exception as e:
                err_str = str(e)
                last_error = err_str
                if not _is_tool_transient(err_str):
                    # Permanent error — don't retry
                    logger.error(f"Tool {tool_call.tool_name} permanent error: {e}")
                    return ToolResult(
                        tool_name=tool_call.tool_name,
                        success=False,
                        error=f"Execution error: {e}",
                    )
                logger.warning(
                    f"Tool {tool_call.tool_name} transient error "
                    f"(attempt {attempt}/{TOOL_MAX_RETRIES}): {e}"
                )

            # Backoff before retry
            if attempt < TOOL_MAX_RETRIES:
                await asyncio.sleep(TOOL_BACKOFF_SECONDS * attempt)

        # All retries exhausted
        logger.error(
            f"Tool {tool_call.tool_name} failed after {TOOL_MAX_RETRIES} "
            f"attempts: {last_error}"
        )
        return ToolResult(
            tool_name=tool_call.tool_name,
            success=False,
            error=f"All {TOOL_MAX_RETRIES} attempts failed: {last_error}",
        )

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        """Return all tool definitions (read-only + active). Used by Remediation."""
        return [
            ReadFileTool.definition(),
            GrepSearchTool.definition(),
            FetchDocsTool.definition(),
            RunDiagnosticsTool.definition(),
            ApplyPatchTool.definition(),
            RestartServiceTool.definition(),
        ]

    def get_read_only_tool_definitions(self) -> list[dict[str, Any]]:
        """Return only read-only tool definitions. Used by Diagnosis.

        The Diagnosis agent must investigate but NEVER modify system state.
        It should not see apply_patch or restart_service as available tools.
        """
        return [
            defn for name, (tool, category) in self._tool_map.items()
            if category == ToolCategory.READ_ONLY
            for defn in [tool.definition()]
        ]

    def get_remediation_tool_definitions(self) -> list[dict[str, Any]]:
        """Return tools for Remediation: read_file + active tools only.

        Excludes grep_search, fetch_docs, run_diagnostics to prevent the LLM
        from wasting tool loops on investigation instead of applying fixes.
        The diagnosis phase already gathered all needed context.
        """
        _REMEDIATION_TOOLS = {"read_file", "apply_patch", "restart_service"}
        return [
            tool.definition()
            for name, (tool, category) in self._tool_map.items()
            if name in _REMEDIATION_TOOLS
        ]
