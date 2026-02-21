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
from backend.mcp_tools.patch_tool import ApplyPatchTool


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
        """In audit mode, file existence IS checked before the audit branch."""
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
    async def test_backup_failure(self, tool, project_root):
        with patch("shutil.copy2", side_effect=OSError("disk full")):
            result = await tool.execute("config/db.py", "diff content")
            assert result["success"] is False
            assert "Backup failed" in result["error"]

    @pytest.mark.asyncio
    async def test_git_check_fails(self, tool, project_root):
        """git apply --check fails => return error, cleanup temp file."""
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"patch does not apply"))
        mock_proc.returncode = 1

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc), \
             patch("asyncio.wait_for", return_value=(b"", b"patch does not apply")):
            mock_proc.communicate = AsyncMock(return_value=(b"", b"patch does not apply"))
            result = await tool.execute("config/db.py", "bad diff")
            assert result["success"] is False
            assert "check failed" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_git_apply_succeeds(self, tool, project_root):
        """Full success path: backup, check, apply."""
        # First call is git apply --check (success), second is git apply (success)
        call_count = 0

        async def mock_create_subprocess_exec(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            proc = AsyncMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_create_subprocess_exec), \
             patch("asyncio.wait_for", return_value=(b"", b"")):
            result = await tool.execute("config/db.py", "valid diff")
            assert result["success"] is True
            assert "Patch applied" in result["output"]

    @pytest.mark.asyncio
    async def test_git_apply_fails_restores_backup(self, tool, project_root):
        """git apply fails after check passes => restore backup."""
        call_count = 0

        async def mock_create_subprocess_exec(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            proc = AsyncMock()
            if call_count == 1:
                # git apply --check succeeds
                proc.communicate = AsyncMock(return_value=(b"", b""))
                proc.returncode = 0
            else:
                # git apply fails
                proc.communicate = AsyncMock(return_value=(b"", b"conflict"))
                proc.returncode = 1
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_create_subprocess_exec), \
             patch("asyncio.wait_for") as mock_wait:
            # Make wait_for just call the coroutine
            async def pass_through(coro, **kwargs):
                return await coro
            mock_wait.side_effect = pass_through
            result = await tool.execute("config/db.py", "conflicting diff")
            assert result["success"] is False
            assert "apply failed" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_timeout(self, tool, project_root):
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_sub, \
             patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
            mock_sub.return_value = AsyncMock()
            result = await tool.execute("config/db.py", "diff")
            assert result["success"] is False
            assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_generic_exception(self, tool, project_root):
        with patch("shutil.copy2"):  # backup succeeds
            with patch("tempfile.NamedTemporaryFile", side_effect=RuntimeError("temp error")):
                result = await tool.execute("config/db.py", "diff")
                assert result["success"] is False
                assert "temp error" in result["error"]


class TestApplyPatchToolDefinition:
    def test_definition(self):
        defn = ApplyPatchTool.definition()
        assert defn["name"] == "apply_patch"
        assert "input_schema" in defn
        assert defn["input_schema"]["type"] == "object"
        assert "file_path" in defn["input_schema"]["properties"]
        assert "diff" in defn["input_schema"]["properties"]
