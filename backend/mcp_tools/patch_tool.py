"""
Apply patch tool - safely applies diffs with backup.
Uses git apply --check for validation.
"""

import asyncio
import logging
import os
import shutil
import tempfile

from backend.shared.security import SecurityGuard

logger = logging.getLogger(__name__)


class ApplyPatchTool:
    """Apply a diff patch to a file with safety checks."""

    def __init__(self, security: SecurityGuard, project_root: str):
        self._security = security
        self._project_root = project_root

    async def execute(self, file_path: str, diff: str) -> dict:
        if not self._security.validate_path(file_path):
            return {"success": False, "error": "Path validation failed"}

        full_path = os.path.join(self._project_root, file_path)
        if not os.path.isfile(full_path):
            return {"success": False, "error": f"File not found: {file_path}"}

        if self._security.is_audit_mode():
            logger.info(f"[AUDIT] Would patch: {file_path}")
            return {
                "success": True,
                "output": f"[AUDIT MODE] Patch logged for: {file_path}",
                "audit_only": True,
            }

        # Create backup
        backup_path = full_path + ".bak"
        try:
            shutil.copy2(full_path, backup_path)
        except OSError as e:
            return {"success": False, "error": f"Backup failed: {e}"}

        # Write diff to temp file and validate with git
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".patch", delete=False
            ) as tmp:
                tmp.write(diff)
                tmp_path = tmp.name

            # Dry-run check
            proc = await asyncio.create_subprocess_exec(
                "git", "apply", "--check", tmp_path,
                cwd=self._project_root,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode != 0:
                os.unlink(tmp_path)
                err = stderr.decode("utf-8", errors="replace")
                return {"success": False, "error": f"Patch check failed: {err}"}

            # Apply patch
            proc = await asyncio.create_subprocess_exec(
                "git", "apply", tmp_path,
                cwd=self._project_root,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            os.unlink(tmp_path)

            if proc.returncode != 0:
                # Restore backup
                shutil.copy2(backup_path, full_path)
                err = stderr.decode("utf-8", errors="replace")
                return {"success": False, "error": f"Patch apply failed: {err}"}

            return {
                "success": True,
                "output": f"Patch applied to {file_path}. Backup at {backup_path}",
            }
        except asyncio.TimeoutError:
            return {"success": False, "error": "Patch operation timed out"}
        except Exception as e:
            logger.error(f"apply_patch error: {e}")
            return {"success": False, "error": str(e)}

    @staticmethod
    def definition() -> dict:
        return {
            "name": "apply_patch",
            "description": "Apply a diff patch to a file. Creates .bak backup.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative path to file",
                    },
                    "diff": {
                        "type": "string",
                        "description": "Unified diff to apply",
                    },
                },
                "required": ["file_path", "diff"],
            },
        }
