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
from typing import Optional

from pydantic import ValidationError

from backend.shared.circuit_breaker import RateLimiter
from backend.shared.config import SecurityConfig, SentryMode
from backend.shared.interfaces import IToolExecutor
from backend.shared.models import ToolCall, ToolCategory, ToolResult
from backend.shared.security import SecurityGuard

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


class MCPToolExecutor(IToolExecutor):
    """Routes tool calls to implementations with security checks."""

    def __init__(self, security: SecurityGuard, project_root: str):
        self._security = security
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

        self._tool_map = {
            "read_file": (self._read_file, ToolCategory.READ_ONLY),
            "grep_search": (self._grep, ToolCategory.READ_ONLY),
            "fetch_docs": (self._fetch, ToolCategory.READ_ONLY),
            "run_diagnostics": (self._diagnostics, ToolCategory.ACTIVE),
            "apply_patch": (self._patch, ToolCategory.ACTIVE),
            "restart_service": (self._restart, ToolCategory.ACTIVE),
        }

    async def execute(self, tool_call: ToolCall) -> ToolResult:
        if self._security.is_stopped():
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error="STOP_SENTRY is active. All operations halted.",
            )

        # Bug fix #14: DISABLED mode should block ALL tool execution
        if self._security.mode == SentryMode.DISABLED:
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

        # Bug fix #10: Enforce audit mode centrally for ACTIVE tools.
        # Individual tools check audit mode themselves, but this provides
        # a safety net at the executor level for any tool that forgets.
        if category == ToolCategory.ACTIVE and self._security.is_audit_mode():
            logger.info(
                f"[AUDIT] Blocked active tool at executor level: "
                f"{tool_call.tool_name}"
            )
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=True,
                output=f"[AUDIT MODE] Tool {tool_call.tool_name} logged but not executed.",
                audit_only=True,
            )

        # --- #3: Pydantic arg validation (single source of truth) ---
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
                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=False,
                    error=f"Invalid arguments: {e}",
                )
        else:
            validated_args = tool_call.arguments

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

                return ToolResult(
                    tool_name=tool_call.tool_name,
                    success=success,
                    output=output,
                    error=error,
                    audit_only=audit_only,
                )
            except asyncio.TimeoutError:
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

    def get_tool_definitions(self) -> list:
        return [
            ReadFileTool.definition(),
            GrepSearchTool.definition(),
            FetchDocsTool.definition(),
            RunDiagnosticsTool.definition(),
            ApplyPatchTool.definition(),
            RestartServiceTool.definition(),
        ]
