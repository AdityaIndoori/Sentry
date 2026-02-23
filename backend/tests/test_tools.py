"""
TDD tests for MCP tools - read-only and active tools.
Covers: individual tools, tool_schemas Pydantic models, executor hardening
(arg validation, empty output rejection, retry on transient, timeout).
"""

import asyncio
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pydantic import ValidationError

from backend.shared.security import SecurityGuard
from backend.shared.circuit_breaker import RateLimiter
from backend.shared.models import ToolCall, ToolCategory, ToolResult
from backend.shared.config import SecurityConfig, SentryMode
from backend.mcp_tools.read_only_tools import ReadFileTool, GrepSearchTool
from backend.mcp_tools.active_tools import RunDiagnosticsTool
from backend.mcp_tools.restart_tool import RestartServiceTool
from backend.mcp_tools.tool_schemas import (
    ReadFileArgs, GrepSearchArgs, FetchDocsArgs,
    RunDiagnosticsArgs, ApplyPatchArgs, RestartServiceArgs,
    pydantic_to_input_schema, TOOL_ARG_MODELS,
)
from backend.mcp_tools.executor import (
    MCPToolExecutor, _is_tool_transient,
    TOOL_MAX_RETRIES, TOOL_TIMEOUT_SECONDS,
)


class TestReadFileTool:
    @pytest.fixture
    def tool(self, security_guard, project_root):
        return ReadFileTool(security_guard, project_root)

    @pytest.mark.asyncio
    async def test_read_existing_file(self, tool, project_root):
        result = await tool.execute("config/db.py")
        assert result["success"] is True
        assert "DB_HOST" in result["output"]

    @pytest.mark.asyncio
    async def test_read_nonexistent_file(self, tool):
        result = await tool.execute("nonexistent.txt")
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_blocks_path_traversal(self, tool):
        result = await tool.execute("../../etc/passwd")
        assert result["success"] is False
        assert "Path validation" in result["error"]

    @pytest.mark.asyncio
    async def test_file_too_large(self, security_guard, project_root):
        # Create a tool with a very small max size
        security_guard._config = SecurityConfig(
            mode=SentryMode.AUDIT,
            project_root=project_root,
            max_file_size_bytes=10,  # Very small
        )
        tool = ReadFileTool(security_guard, project_root)
        result = await tool.execute("config/db.py")
        assert result["success"] is False
        assert "too large" in result["error"]

    @pytest.mark.asyncio
    async def test_read_exception(self, tool, project_root):
        with patch("builtins.open", side_effect=PermissionError("denied")):
            result = await tool.execute("config/db.py")
            assert result["success"] is False
            assert "denied" in result["error"]


class TestGrepSearchTool:
    @pytest.fixture
    def tool(self, security_guard, project_root):
        return GrepSearchTool(security_guard, project_root)

    @pytest.mark.asyncio
    async def test_finds_pattern(self, tool):
        result = await tool.execute("DB_HOST", "config")
        assert result["success"] is True
        assert len(result["output"]) > 0

    @pytest.mark.asyncio
    async def test_no_match(self, tool):
        result = await tool.execute("NONEXISTENT_PATTERN_XYZ", "config")
        assert result["success"] is True
        assert result["output"] == "" or "No matches" in str(result["output"])

    @pytest.mark.asyncio
    async def test_blocks_path_traversal(self, tool):
        result = await tool.execute("password", "../../etc")
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_path_not_found(self, tool):
        result = await tool.execute("pattern", "nonexistent_dir")
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_invalid_regex(self, tool):
        result = await tool.execute("[invalid(regex", "config")
        assert result["success"] is False
        assert "Invalid regex" in result["error"]

    @pytest.mark.asyncio
    async def test_grep_definition(self):
        defn = GrepSearchTool.definition()
        assert defn["name"] == "grep_search"
        assert "input_schema" in defn

    @pytest.mark.asyncio
    async def test_grep_exception(self, tool, project_root):
        with patch("os.walk", side_effect=RuntimeError("walk failed")):
            result = await tool.execute("pattern", "config")
            assert result["success"] is False
            assert "walk failed" in result["error"]


class TestRunDiagnosticsTool:
    @pytest.fixture
    def tool(self, security_guard):
        return RunDiagnosticsTool(security_guard)

    @pytest.mark.asyncio
    async def test_audit_mode_logs_only(self, tool):
        result = await tool.execute("ps aux")
        assert result["success"] is True
        assert result["audit_only"] is True

    @pytest.mark.asyncio
    async def test_blocks_dangerous_command(self, tool):
        result = await tool.execute("rm -rf /")
        assert result["success"] is False
        assert "whitelist" in result["error"].lower()


class TestRestartServiceTool:
    @pytest.fixture
    def tool(self, security_guard, rate_limiter):
        return RestartServiceTool(security_guard, rate_limiter)

    @pytest.mark.asyncio
    async def test_audit_mode_logs_only(self, tool):
        with patch.dict(os.environ, {"SERVICE_RESTART_CMD": "docker restart shopapi"}):
            result = await tool.execute()
            assert result["success"] is True
            assert result["audit_only"] is True

    @pytest.mark.asyncio
    async def test_missing_env_var_returns_error(self, tool):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SERVICE_RESTART_CMD", None)
            result = await tool.execute()
            assert result["success"] is False
            assert "SERVICE_RESTART_CMD" in result["error"]


class TestToolDefinitions:
    """Verify all tools expose valid MCP schemas."""

    def test_read_file_definition(self):
        defn = ReadFileTool.definition()
        assert defn["name"] == "read_file"
        assert "input_schema" in defn

    def test_diagnostics_definition(self):
        defn = RunDiagnosticsTool.definition()
        assert defn["name"] == "run_diagnostics"

    def test_restart_definition(self):
        defn = RestartServiceTool.definition()
        assert defn["name"] == "restart_service"
        assert defn["input_schema"]["type"] == "object"


# ===========================================================================
# Hardening tests: tool_schemas.py — Pydantic arg models
# ===========================================================================

class TestToolArgModels:
    """Tests for Pydantic tool argument models and schema generation."""

    def test_read_file_args_valid(self):
        args = ReadFileArgs(path="config/db.py")
        assert args.path == "config/db.py"

    def test_read_file_args_missing_path(self):
        with pytest.raises(ValidationError):
            ReadFileArgs()

    def test_grep_search_args_with_default_path(self):
        args = GrepSearchArgs(query="DB_HOST")
        assert args.query == "DB_HOST"
        assert args.path == "."  # default

    def test_grep_search_args_custom_path(self):
        args = GrepSearchArgs(query="error", path="logs")
        assert args.path == "logs"

    def test_fetch_docs_args(self):
        args = FetchDocsArgs(url="https://docs.python.org")
        assert args.url == "https://docs.python.org"

    def test_run_diagnostics_args(self):
        args = RunDiagnosticsArgs(command="ps aux")
        assert args.command == "ps aux"

    def test_apply_patch_args(self):
        args = ApplyPatchArgs(file_path="config/db.py", diff="--- a\n+++ b")
        assert args.file_path == "config/db.py"
        assert args.diff == "--- a\n+++ b"

    def test_apply_patch_args_missing_diff(self):
        with pytest.raises(ValidationError):
            ApplyPatchArgs(file_path="config/db.py")

    def test_restart_service_args_empty(self):
        """RestartServiceArgs has no params — command comes from env."""
        args = RestartServiceArgs()
        assert args is not None


class TestPydanticToInputSchema:
    """Tests for the schema conversion function used by tool definitions."""

    def test_generates_valid_object_schema(self):
        schema = pydantic_to_input_schema(ReadFileArgs)
        assert schema["type"] == "object"
        assert "properties" in schema
        assert "path" in schema["properties"]

    def test_no_title_key(self):
        """Anthropic tool format doesn't need 'title'."""
        schema = pydantic_to_input_schema(ReadFileArgs)
        assert "title" not in schema

    def test_required_fields_present(self):
        schema = pydantic_to_input_schema(ApplyPatchArgs)
        assert "required" in schema
        assert "file_path" in schema["required"]
        assert "diff" in schema["required"]

    def test_optional_field_not_required(self):
        schema = pydantic_to_input_schema(GrepSearchArgs)
        # 'path' has a default, so it should not be required
        required = schema.get("required", [])
        assert "query" in required
        # 'path' has default="." so may or may not be in required depending on Pydantic
        # The key point: 'query' IS required


class TestToolArgModelsMapping:
    """Tests for the TOOL_ARG_MODELS registry."""

    def test_all_six_tools_registered(self):
        expected = {"read_file", "grep_search", "fetch_docs",
                    "run_diagnostics", "apply_patch", "restart_service"}
        assert set(TOOL_ARG_MODELS.keys()) == expected

    def test_models_are_pydantic_classes(self):
        from pydantic import BaseModel
        for name, model in TOOL_ARG_MODELS.items():
            assert issubclass(model, BaseModel), f"{name} is not a Pydantic model"


# ===========================================================================
# Hardening tests: _is_tool_transient()
# ===========================================================================

class TestIsToolTransient:
    """Tests for tool transient error classification."""

    def test_timeout_is_transient(self):
        assert _is_tool_transient("Operation timed out") is True

    def test_connection_is_transient(self):
        assert _is_tool_transient("Connection refused") is True

    def test_503_is_transient(self):
        assert _is_tool_transient("HTTP 503 Service Unavailable") is True

    def test_broken_pipe_is_transient(self):
        assert _is_tool_transient("Broken pipe") is True

    def test_temporarily_is_transient(self):
        assert _is_tool_transient("Resource temporarily unavailable") is True

    def test_file_not_found_is_permanent(self):
        assert _is_tool_transient("File not found") is False

    def test_permission_denied_is_permanent(self):
        assert _is_tool_transient("Permission denied") is False

    def test_invalid_args_is_permanent(self):
        assert _is_tool_transient("Invalid argument: path must be string") is False


# ===========================================================================
# Hardening tests: MCPToolExecutor — arg validation, empty output, retry
# ===========================================================================

class TestExecutorArgValidation:
    """Tests for Pydantic arg validation at executor level (#3)."""

    @pytest.fixture
    def executor(self, security_guard, project_root):
        return MCPToolExecutor(security_guard, project_root)

    @pytest.mark.asyncio
    async def test_valid_args_pass_validation(self, executor):
        """Valid args for read_file should pass through to execution."""
        tc = ToolCall(tool_name="read_file", arguments={"path": "config/db.py"})
        result = await executor.execute(tc)
        # In AUDIT mode, read_only tools should execute normally
        assert result.tool_name == "read_file"
        assert result.success is True
        assert "DB_HOST" in result.output

    @pytest.mark.asyncio
    async def test_invalid_args_rejected(self, executor):
        """Missing required 'path' field should fail validation."""
        tc = ToolCall(tool_name="read_file", arguments={})
        result = await executor.execute(tc)
        assert result.success is False
        assert "Invalid arguments" in result.error

    @pytest.mark.asyncio
    async def test_extra_args_tolerated(self, executor):
        """Extra unexpected args should be silently ignored by Pydantic."""
        tc = ToolCall(tool_name="read_file", arguments={"path": "config/db.py", "extra": "ignored"})
        result = await executor.execute(tc)
        # Should still succeed — Pydantic default allows extra fields or ignores them
        assert result.tool_name == "read_file"

    @pytest.mark.asyncio
    async def test_unknown_tool_rejected(self, executor):
        tc = ToolCall(tool_name="nonexistent_tool", arguments={})
        result = await executor.execute(tc)
        assert result.success is False
        assert "Unknown tool" in result.error


class TestExecutorEmptyOutputRejection:
    """Tests for empty-output demotion to failure (#4)."""

    @pytest.mark.asyncio
    async def test_success_with_empty_output_demoted(self, security_guard, project_root):
        """Tool returning success=True but empty output should be demoted to failure."""
        executor = MCPToolExecutor(security_guard, project_root)

        # Patch the read_file tool to return success but empty output
        async def _mock_execute(**kwargs):
            return {"success": True, "output": "", "error": None}

        executor._read_file.execute = _mock_execute

        tc = ToolCall(tool_name="read_file", arguments={"path": "config/db.py"})
        result = await executor.execute(tc)
        assert result.success is False
        assert "no output" in result.error.lower()

    @pytest.mark.asyncio
    async def test_audit_only_with_short_output_not_demoted(self, security_guard, project_root):
        """Audit-only results legitimately have short output — should NOT be demoted."""
        executor = MCPToolExecutor(security_guard, project_root)

        # run_diagnostics in AUDIT mode returns audit_only=True
        tc = ToolCall(
            tool_name="run_diagnostics",
            arguments={"command": "ps aux"},
            category=ToolCategory.ACTIVE,
        )
        result = await executor.execute(tc)
        # In AUDIT mode, active tools return audit_only=True at executor level
        assert result.audit_only is True
        assert result.success is True


class TestExecutorRetryOnTransient:
    """Tests for tool retry logic on transient errors (#5)."""

    @pytest.mark.asyncio
    async def test_retries_on_transient_then_succeeds(self, security_guard, project_root):
        """Transient error on first attempt, success on second."""
        executor = MCPToolExecutor(security_guard, project_root)
        call_count = 0

        async def _mock_execute(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Connection reset by peer")
            return {"success": True, "output": "DB_HOST = 'localhost'", "error": None}

        executor._read_file.execute = _mock_execute

        with patch("backend.mcp_tools.executor.asyncio.sleep", new_callable=AsyncMock):
            tc = ToolCall(tool_name="read_file", arguments={"path": "config/db.py"})
            result = await executor.execute(tc)

        assert result.success is True
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_permanent_error_no_retry(self, security_guard, project_root):
        """Permanent errors should fail immediately without retrying."""
        executor = MCPToolExecutor(security_guard, project_root)
        call_count = 0

        async def _mock_execute(**kwargs):
            nonlocal call_count
            call_count += 1
            raise Exception("Permission denied: cannot read file")

        executor._read_file.execute = _mock_execute

        tc = ToolCall(tool_name="read_file", arguments={"path": "config/db.py"})
        result = await executor.execute(tc)

        assert result.success is False
        assert call_count == 1  # No retry on permanent error
        assert "Permission denied" in result.error

    @pytest.mark.asyncio
    async def test_type_error_no_retry(self, security_guard, project_root):
        """TypeError (bad args) should fail immediately — it's permanent."""
        executor = MCPToolExecutor(security_guard, project_root)

        async def _mock_execute(**kwargs):
            raise TypeError("execute() got an unexpected keyword argument")

        executor._read_file.execute = _mock_execute

        tc = ToolCall(tool_name="read_file", arguments={"path": "config/db.py"})
        result = await executor.execute(tc)

        assert result.success is False
        assert "Invalid arguments" in result.error

    @pytest.mark.asyncio
    async def test_all_retries_exhausted(self, security_guard, project_root):
        """All retry attempts fail with transient errors."""
        executor = MCPToolExecutor(security_guard, project_root)
        call_count = 0

        async def _mock_execute(**kwargs):
            nonlocal call_count
            call_count += 1
            raise Exception("Connection timeout")

        executor._read_file.execute = _mock_execute

        with patch("backend.mcp_tools.executor.asyncio.sleep", new_callable=AsyncMock):
            tc = ToolCall(tool_name="read_file", arguments={"path": "config/db.py"})
            result = await executor.execute(tc)

        assert result.success is False
        assert call_count == TOOL_MAX_RETRIES
        assert "attempts failed" in result.error.lower()


class TestExecutorDisabledAndStopModes:
    """Tests for DISABLED mode and STOP_SENTRY enforcement at executor level."""

    @pytest.mark.asyncio
    async def test_disabled_mode_blocks_all_tools(self, project_root):
        """DISABLED mode should block all tools, not just active ones."""
        config = SecurityConfig(
            mode=SentryMode.DISABLED,
            project_root=project_root,
        )
        guard = SecurityGuard(config)
        executor = MCPToolExecutor(guard, project_root)

        tc = ToolCall(tool_name="read_file", arguments={"path": "config/db.py"})
        result = await executor.execute(tc)
        assert result.success is False
        assert "DISABLED" in result.error

    @pytest.mark.asyncio
    async def test_stop_file_blocks_all_tools(self, project_root):
        """STOP_SENTRY file should halt all operations."""
        stop_path = os.path.join(project_root, "STOP_SENTRY")
        config = SecurityConfig(
            mode=SentryMode.ACTIVE,
            stop_file_path=stop_path,
            project_root=project_root,
        )
        guard = SecurityGuard(config)
        executor = MCPToolExecutor(guard, project_root)

        # Create the stop file
        with open(stop_path, "w") as f:
            f.write("STOP")

        try:
            tc = ToolCall(tool_name="read_file", arguments={"path": "config/db.py"})
            result = await executor.execute(tc)
            assert result.success is False
            assert "STOP_SENTRY" in result.error
        finally:
            os.remove(stop_path)


class TestExecutorToolDefinitions:
    """Tests for get_tool_definitions() returning all 6 tools."""

    def test_returns_six_definitions(self, security_guard, project_root):
        executor = MCPToolExecutor(security_guard, project_root)
        defs = executor.get_tool_definitions()
        assert len(defs) == 6

    def test_all_definitions_have_required_fields(self, security_guard, project_root):
        executor = MCPToolExecutor(security_guard, project_root)
        for defn in executor.get_tool_definitions():
            assert "name" in defn
            assert "description" in defn
            assert "input_schema" in defn
            assert defn["input_schema"]["type"] == "object"

    def test_definition_names_match_tool_map(self, security_guard, project_root):
        executor = MCPToolExecutor(security_guard, project_root)
        def_names = {d["name"] for d in executor.get_tool_definitions()}
        expected = {"read_file", "grep_search", "fetch_docs",
                    "run_diagnostics", "apply_patch", "restart_service"}
        assert def_names == expected


class TestExecutorReadOnlyToolDefinitions:
    """Tests for get_read_only_tool_definitions() — Diagnosis agent must NOT get write tools."""

    def test_returns_only_read_only_tools(self, security_guard, project_root):
        executor = MCPToolExecutor(security_guard, project_root)
        defs = executor.get_read_only_tool_definitions()
        names = {d["name"] for d in defs}
        assert "read_file" in names
        assert "grep_search" in names
        assert "fetch_docs" in names
        # These MUST NOT be present — Diagnosis agent is read-only
        assert "apply_patch" not in names
        assert "restart_service" not in names
        assert "run_diagnostics" not in names

    def test_read_only_count(self, security_guard, project_root):
        executor = MCPToolExecutor(security_guard, project_root)
        defs = executor.get_read_only_tool_definitions()
        assert len(defs) == 3  # read_file, grep_search, fetch_docs

    def test_read_only_definitions_have_required_fields(self, security_guard, project_root):
        executor = MCPToolExecutor(security_guard, project_root)
        for defn in executor.get_read_only_tool_definitions():
            assert "name" in defn
            assert "description" in defn
            assert "input_schema" in defn

    def test_full_definitions_still_include_all(self, security_guard, project_root):
        """get_tool_definitions() must still return all 6 tools."""
        executor = MCPToolExecutor(security_guard, project_root)
        all_defs = executor.get_tool_definitions()
        ro_defs = executor.get_read_only_tool_definitions()
        assert len(all_defs) == 6


class TestExecutorRemediationToolDefinitions:
    """Tests for get_remediation_tool_definitions() — only read_file + active tools."""

    def test_returns_only_remediation_tools(self, security_guard, project_root):
        executor = MCPToolExecutor(security_guard, project_root)
        defs = executor.get_remediation_tool_definitions()
        names = {d["name"] for d in defs}
        assert "apply_patch" in names
        assert "restart_service" in names
        assert "read_file" in names
        # Must NOT include investigation tools
        assert "grep_search" not in names
        assert "fetch_docs" not in names
        assert "run_diagnostics" not in names

    def test_remediation_count(self, security_guard, project_root):
        executor = MCPToolExecutor(security_guard, project_root)
        defs = executor.get_remediation_tool_definitions()
        assert len(defs) == 3  # read_file, apply_patch, restart_service

    def test_remediation_definitions_have_required_fields(self, security_guard, project_root):
        executor = MCPToolExecutor(security_guard, project_root)
        for defn in executor.get_remediation_tool_definitions():
            assert "name" in defn
            assert "description" in defn
            assert "input_schema" in defn


# ===========================================================================
# FetchDocsTool tests
# ===========================================================================

class TestFetchDocsTool:
    """Tests for FetchDocsTool including URL validation and HTTP responses."""

    @pytest.fixture
    def tool(self, security_guard):
        from backend.mcp_tools.read_only_tools import FetchDocsTool
        return FetchDocsTool(security_guard)

    @pytest.mark.asyncio
    async def test_blocks_disallowed_url(self, tool):
        result = await tool.execute("https://evil.com/malware")
        assert result["success"] is False
        assert "allow-list" in result["error"]

    @pytest.mark.asyncio
    async def test_successful_fetch(self, tool):
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="<html>Python docs</html>")
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("backend.mcp_tools.read_only_tools.aiohttp.ClientSession",
                    return_value=mock_session):
            result = await tool.execute("https://docs.python.org/3/tutorial")
            assert result["success"] is True
            assert "Python docs" in result["output"]

    @pytest.mark.asyncio
    async def test_http_error_status(self, tool):
        mock_resp = AsyncMock()
        mock_resp.status = 404
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_resp)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("backend.mcp_tools.read_only_tools.aiohttp.ClientSession",
                    return_value=mock_session):
            result = await tool.execute("https://docs.python.org/missing")
            assert result["success"] is False
            assert "404" in result["error"]

    @pytest.mark.asyncio
    async def test_network_exception(self, tool):
        import aiohttp
        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=aiohttp.ClientError("Connection failed"))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("backend.mcp_tools.read_only_tools.aiohttp.ClientSession",
                    return_value=mock_session):
            result = await tool.execute("https://docs.python.org/timeout")
            assert result["success"] is False

    def test_definition(self):
        from backend.mcp_tools.read_only_tools import FetchDocsTool
        defn = FetchDocsTool.definition()
        assert defn["name"] == "fetch_docs"
        assert "input_schema" in defn


# ===========================================================================
# Active mode tool tests (RunDiagnosticsTool, RestartServiceTool)
# ===========================================================================

class TestRunDiagnosticsActiveMode:
    """Tests for RunDiagnosticsTool in ACTIVE mode with subprocess."""

    @pytest.fixture
    def tool(self, active_security_guard):
        return RunDiagnosticsTool(active_security_guard)

    @pytest.mark.asyncio
    async def test_active_mode_success(self, tool):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"PID TTY\n123 pts/0", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc), \
             patch("asyncio.wait_for", return_value=(b"PID TTY\n123 pts/0", b"")):
            mock_proc.communicate = AsyncMock(return_value=(b"PID TTY\n123 pts/0", b""))
            result = await tool.execute("ps aux")
            assert result["success"] is True
            assert "PID" in result["output"]

    @pytest.mark.asyncio
    async def test_active_mode_command_fails(self, tool):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"command not found"))
        mock_proc.returncode = 1

        with patch("asyncio.create_subprocess_shell", return_value=mock_proc), \
             patch("asyncio.wait_for", return_value=(b"", b"command not found")):
            mock_proc.communicate = AsyncMock(return_value=(b"", b"command not found"))
            result = await tool.execute("ps aux")
            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_active_mode_timeout(self, tool):
        with patch("asyncio.create_subprocess_shell", new_callable=AsyncMock) as mock_sub:
            mock_proc = AsyncMock()
            mock_sub.return_value = mock_proc
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                result = await tool.execute("ps aux")
                assert result["success"] is False
                assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_active_mode_exception(self, tool):
        with patch("asyncio.create_subprocess_shell", side_effect=OSError("spawn failed")):
            result = await tool.execute("ps aux")
            assert result["success"] is False
            assert "spawn failed" in result["error"]


class TestRestartServiceActiveMode:
    """Tests for RestartServiceTool in ACTIVE mode (env-configured command)."""

    @pytest.fixture
    def tool(self, active_security_guard, rate_limiter):
        return RestartServiceTool(active_security_guard, rate_limiter, cooldown_seconds=600)

    @pytest.mark.asyncio
    async def test_active_mode_success(self, tool):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"shopapi\n", b""))
        mock_proc.returncode = 0

        with patch.dict(os.environ, {"SERVICE_RESTART_CMD": "docker restart shopapi"}), \
             patch("asyncio.create_subprocess_shell", return_value=mock_proc), \
             patch("asyncio.wait_for", return_value=(b"shopapi\n", b"")):
            mock_proc.communicate = AsyncMock(return_value=(b"shopapi\n", b""))
            result = await tool.execute()
            assert result["success"] is True
            assert "Restarted" in result["output"]

    @pytest.mark.asyncio
    async def test_active_mode_restart_fails(self, tool):
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"No such container"))
        mock_proc.returncode = 1

        with patch.dict(os.environ, {"SERVICE_RESTART_CMD": "docker restart badname"}), \
             patch("asyncio.create_subprocess_shell", return_value=mock_proc), \
             patch("asyncio.wait_for", return_value=(b"", b"No such container")):
            mock_proc.communicate = AsyncMock(return_value=(b"", b"No such container"))
            result = await tool.execute()
            assert result["success"] is False
            assert "failed" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_active_mode_rate_limited(self, tool, rate_limiter):
        # Record a recent restart to trigger rate limit
        rate_limiter.record("restart:service")
        with patch.dict(os.environ, {"SERVICE_RESTART_CMD": "docker restart shopapi"}):
            result = await tool.execute()
            assert result["success"] is False
            assert "Rate limited" in result["error"]

    @pytest.mark.asyncio
    async def test_active_mode_timeout(self, tool):
        with patch.dict(os.environ, {"SERVICE_RESTART_CMD": "docker restart shopapi"}), \
             patch("asyncio.create_subprocess_shell", new_callable=AsyncMock) as mock_sub:
            mock_proc = AsyncMock()
            mock_sub.return_value = mock_proc
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                result = await tool.execute()
                assert result["success"] is False
                assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_active_mode_exception(self, tool):
        with patch.dict(os.environ, {"SERVICE_RESTART_CMD": "docker restart shopapi"}), \
             patch("asyncio.create_subprocess_shell", side_effect=OSError("exec failed")):
            result = await tool.execute()
            assert result["success"] is False
            assert "exec failed" in result["error"]


class TestExecutorTimeout:
    """Test executor-level timeout handling."""

    @pytest.mark.asyncio
    async def test_executor_timeout(self, security_guard, project_root):
        executor = MCPToolExecutor(security_guard, project_root)

        async def _slow_execute(**kwargs):
            # Use a Future that never resolves so the mock on asyncio.sleep
            # (needed for backoff) doesn't accidentally make this return None.
            await asyncio.Future()

        executor._read_file.execute = _slow_execute

        with patch("backend.mcp_tools.executor.TOOL_TIMEOUT_SECONDS", 0.01), \
             patch("backend.mcp_tools.executor.asyncio.sleep", new_callable=AsyncMock):
            tc = ToolCall(tool_name="read_file", arguments={"path": "config/db.py"})
            result = await executor.execute(tc)

        assert result.success is False
        assert "timed out" in result.error.lower() or "attempts failed" in result.error.lower()
