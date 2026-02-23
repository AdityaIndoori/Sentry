"""
Tests for mcp_tools/patch_tool.py — Apply patch tool (audit + active mode).
"""

import asyncio
import os
import shutil
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from backend.shared.security import SecurityGuard
from backend.shared.config import SecurityConfig, SentryMode
from backend.mcp_tools.patch_tool import ApplyPatchTool, _apply_unified_diff


class TestApplyUnifiedDiff:
    """Tests for the pure-Python unified diff applier."""

    def test_simple_replacement(self):
        original = "line1\nline2\nline3\nline4"
        diff = (
            "--- a/test.py\n"
            "+++ b/test.py\n"
            "@@ -1,4 +1,4 @@\n"
            " line1\n"
            "-line2\n"
            "+replaced2\n"
            " line3\n"
            " line4\n"
        )
        result = _apply_unified_diff(original, diff)
        assert result is not None
        assert "replaced2" in result
        assert "line2" not in result

    def test_addition(self):
        original = "line1\nline2\nline3"
        diff = (
            "--- a/test.py\n"
            "+++ b/test.py\n"
            "@@ -1,3 +1,4 @@\n"
            " line1\n"
            " line2\n"
            "+new_line\n"
            " line3\n"
        )
        result = _apply_unified_diff(original, diff)
        assert result is not None
        assert "new_line" in result

    def test_no_hunks_returns_none(self):
        result = _apply_unified_diff("hello\n", "no hunks here\n")
        assert result is None

    def test_unmatched_context_returns_none(self):
        original = "aaa\nbbb\nccc"
        diff = (
            "--- a/test.py\n"
            "+++ b/test.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-zzz_does_not_exist\n"
            "+replacement\n"
        )
        result = _apply_unified_diff(original, diff)
        assert result is None


class TestApplyPatchToolAuditMode:
    @pytest.fixture
    def tool(self, security_guard, project_root):
        return ApplyPatchTool(security_guard, project_root)

    @pytest.mark.asyncio
    async def test_audit_mode_logs_intent(self, tool):
        result = await tool.execute("config/db.py", "--- a\n+++ b\n@@ -1 +1 @@")
        assert result["success"] is True
        assert result["audit_only"] is True
        assert "AUDIT" in result["output"]

    @pytest.mark.asyncio
    async def test_blocks_path_traversal(self, tool):
        result = await tool.execute("../../etc/passwd", "diff content")
        assert result["success"] is False
        assert "Path validation" in result["error"]

    @pytest.mark.asyncio
    async def test_file_not_found_audit_mode(self, tool):
        result = await tool.execute("nonexistent.py", "diff content")
        assert result["success"] is False
        assert "not found" in result["error"].lower()


class TestApplyPatchToolActiveMode:
    @pytest.fixture
    def tool(self, active_security_guard, project_root):
        return ApplyPatchTool(active_security_guard, project_root)

    @pytest.mark.asyncio
    async def test_file_not_found_in_active_mode(self, tool):
        result = await tool.execute("nonexistent.py", "diff content")
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_backup_failure_proceeds(self, tool, project_root):
        """Backup failure logs warning but proceeds."""
        with patch.object(tool, "_try_git_apply", return_value={"success": True}):
            with patch("shutil.copyfile", side_effect=OSError("disk full")):
                result = await tool.execute("config/db.py", "valid diff")
                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_git_apply_succeeds(self, tool, project_root):
        """Full success path through git apply."""
        with patch.object(tool, "_try_git_apply", return_value={"success": True}):
            result = await tool.execute("config/db.py", "valid diff")
            assert result["success"] is True
            assert "(git)" in result["output"]

    @pytest.mark.asyncio
    async def test_python_fallback_on_git_failure(self, tool, project_root):
        """When git fails, python fallback should be tried."""
        with open(os.path.join(project_root, "config", "db.py"), "r") as f:
            content = f.read()
        lines = content.split("\n")
        first_line = lines[0]
        second_line = lines[1] if len(lines) > 1 else ""

        diff = (
            "--- a/config/db.py\n"
            "+++ b/config/db.py\n"
            "@@ -1,2 +1,2 @@\n"
            f" {first_line}\n"
            f"-{second_line}\n"
            f"+{second_line}\n"
        )
        with patch.object(tool, "_try_git_apply", return_value={"success": False, "error": "corrupt"}):
            result = await tool.execute("config/db.py", diff)
            assert result["success"] is True
            assert "(python)" in result["output"]

    @pytest.mark.asyncio
    async def test_both_methods_fail(self, tool, project_root):
        """When both git and python fail, error is returned."""
        with patch.object(tool, "_try_git_apply", return_value={"success": False, "error": "corrupt"}):
            result = await tool.execute("config/db.py", "bad diff with no hunks")
            assert result["success"] is False
            assert "could not match" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_generic_exception(self, tool, project_root):
        """Exception during processing should be caught."""
        with patch.object(tool, "_try_git_apply", side_effect=RuntimeError("unexpected")):
            result = await tool.execute("config/db.py", "diff")
            assert result["success"] is False
            assert "unexpected" in result["error"]


class TestApplyPatchToolDefinition:
    def test_definition(self):
        defn = ApplyPatchTool.definition()
        assert defn["name"] == "apply_patch"
        assert "input_schema" in defn
        assert defn["input_schema"]["type"] == "object"
        assert "file_path" in defn["input_schema"]["properties"]
        assert "diff" in defn["input_schema"]["properties"]
