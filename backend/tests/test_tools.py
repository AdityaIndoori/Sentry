"""
TDD tests for MCP tools - read-only and active tools.
"""

import os
import pytest
from backend.shared.security import SecurityGuard
from backend.shared.circuit_breaker import RateLimiter
from backend.mcp_tools.read_only_tools import ReadFileTool, GrepSearchTool
from backend.mcp_tools.active_tools import RunDiagnosticsTool
from backend.mcp_tools.restart_tool import RestartServiceTool


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
        result = await tool.execute("nginx")
        assert result["success"] is True
        assert result["audit_only"] is True

    @pytest.mark.asyncio
    async def test_blocks_invalid_service_name(self, tool):
        result = await tool.execute("nginx; rm -rf /")
        assert result["success"] is False
        assert "Invalid" in result["error"]

    @pytest.mark.asyncio
    async def test_blocks_special_chars(self, tool):
        result = await tool.execute("../../../etc")
        assert result["success"] is False


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
        assert "service_name" in defn["input_schema"]["properties"]
