"""
Tool executor - routes tool calls to appropriate handlers.
Implements IToolExecutor interface (Dependency Inversion).
"""

import logging
from typing import Optional

from backend.shared.circuit_breaker import RateLimiter
from backend.shared.config import SecurityConfig
from backend.shared.interfaces import IToolExecutor
from backend.shared.models import ToolCall, ToolCategory, ToolResult
from backend.shared.security import SecurityGuard

from .active_tools import RunDiagnosticsTool
from .patch_tool import ApplyPatchTool
from .read_only_tools import FetchDocsTool, GrepSearchTool, ReadFileTool
from .restart_tool import RestartServiceTool

logger = logging.getLogger(__name__)


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

        entry = self._tool_map.get(tool_call.tool_name)
        if not entry:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=f"Unknown tool: {tool_call.tool_name}",
            )

        tool, category = entry
        logger.info(
            f"Executing tool: {tool_call.tool_name} "
            f"(category={category.value})"
        )

        try:
            result = await tool.execute(**tool_call.arguments)
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=result.get("success", False),
                output=result.get("output", ""),
                error=result.get("error"),
                audit_only=result.get("audit_only", False),
            )
        except TypeError as e:
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=f"Invalid arguments: {e}",
            )
        except Exception as e:
            logger.error(f"Tool execution error: {e}")
            return ToolResult(
                tool_name=tool_call.tool_name,
                success=False,
                error=f"Execution error: {e}",
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
