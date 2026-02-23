"""
Apply patch tool - safely applies unified diffs to files.
Uses git apply when available, with pure-Python fallback for robustness.
"""

import asyncio
import logging
import os
import re
import shutil
import tempfile

from backend.shared.security import SecurityGuard
from backend.mcp_tools.tool_schemas import ApplyPatchArgs, pydantic_to_input_schema

logger = logging.getLogger(__name__)


def _apply_unified_diff(original: str, diff: str) -> str | None:
    """
    Pure-Python unified diff applier.
    Parses @@ hunks and applies additions/removals to the original text.
    Returns the patched text, or None if the diff can't be applied.
    """
    lines = original.split("\n")
    diff_lines = diff.split("\n")

    # Find hunk headers
    hunks = []
    i = 0
    while i < len(diff_lines):
        m = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", diff_lines[i])
        if m:
            start = int(m.group(1))
            hunk_lines = []
            i += 1
            while i < len(diff_lines):
                line = diff_lines[i]
                if line.startswith("@@") or line.startswith("diff ") or line.startswith("---") or line.startswith("+++"):
                    break
                hunk_lines.append(line)
                i += 1
            hunks.append((start, hunk_lines))
        else:
            i += 1

    if not hunks:
        return None

    # Apply hunks in reverse order so line numbers stay valid
    result = list(lines)
    for start_line, hunk_lines in reversed(hunks):
        idx = start_line - 1  # Convert 1-indexed to 0-indexed

        # Build removal and addition lists from the hunk
        removals = []
        additions = []
        context_offset = 0
        new_block = []

        for hl in hunk_lines:
            if not hl and not new_block:
                # Skip leading empty lines
                continue
            if hl.startswith("-"):
                new_block.append(("remove", hl[1:]))
            elif hl.startswith("+"):
                new_block.append(("add", hl[1:]))
            elif hl.startswith(" "):
                new_block.append(("context", hl[1:]))
            elif hl.startswith("\\"):
                # "\ No newline at end of file" — skip
                continue
            # Skip empty lines that appear at end of hunk (trailing newline artifacts)

        # Reconstruct the section: replace old lines with new lines
        # Walk through the hunk and build the replacement
        old_section = []
        new_section = []
        for kind, content in new_block:
            if kind == "remove":
                old_section.append(content)
            elif kind == "add":
                new_section.append(content)
            elif kind == "context":
                old_section.append(content)
                new_section.append(content)

        # Find the best match position (fuzzy: try exact first, then strip-match)
        match_pos = None
        for offset in range(0, min(20, len(result))):
            for sign in (0, -1, 1):
                try_pos = idx + offset * sign
                if try_pos < 0 or try_pos + len(old_section) > len(result):
                    continue
                # Compare stripped lines for fuzzy matching
                if all(
                    result[try_pos + j].rstrip() == old_section[j].rstrip()
                    for j in range(len(old_section))
                ):
                    match_pos = try_pos
                    break
            if match_pos is not None:
                break

        if match_pos is None:
            logger.warning(f"Could not match hunk at line {start_line}")
            return None

        # Replace
        result[match_pos:match_pos + len(old_section)] = new_section

    return "\n".join(result)


class ApplyPatchTool:
    """Apply a diff patch to a file with safety checks."""

    def __init__(self, security: SecurityGuard, project_root: str):
        self._security = security
        self._project_root = project_root

    async def execute(self, file_path: str, diff: str) -> dict:
        file_path = self._security.sanitize_input(file_path)
        # Note: diff content is NOT sanitized — diffs legitimately contain special characters
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
            shutil.copyfile(full_path, backup_path)
        except OSError as e:
            logger.warning(f"Backup failed for {file_path}: {e} — proceeding without backup")
            backup_path = None

        # Normalize diff
        if diff and not diff.endswith("\n"):
            diff += "\n"
        diff = diff.replace("\r\n", "\n")

        try:
            # Read the original file
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                original = f.read()

            # Try git apply first (fast, reliable when it works)
            git_result = await self._try_git_apply(diff)
            if git_result is not None:
                if git_result["success"]:
                    backup_msg = f" Backup at {backup_path}" if backup_path else ""
                    return {"success": True, "output": f"Patch applied to {file_path} (git).{backup_msg}"}
                # git apply failed — fall through to Python fallback
                logger.info(f"git apply failed ({git_result['error'][:80]}), trying Python fallback")

            # Pure-Python fallback: parse the unified diff and apply it
            patched = _apply_unified_diff(original, diff)
            if patched is None:
                # Restore backup if we have one
                if backup_path and os.path.isfile(backup_path):
                    shutil.copyfile(backup_path, full_path)
                return {"success": False, "error": "Could not match diff hunks to file content"}

            # Write the patched content
            with open(full_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(patched)

            backup_msg = f" Backup at {backup_path}" if backup_path else ""
            return {"success": True, "output": f"Patch applied to {file_path} (python).{backup_msg}"}

        except asyncio.TimeoutError:
            return {"success": False, "error": "Patch operation timed out"}
        except Exception as e:
            logger.error(f"apply_patch error: {e}")
            # Restore backup on error
            if backup_path and os.path.isfile(backup_path):
                try:
                    shutil.copyfile(backup_path, full_path)
                except OSError:
                    pass
            return {"success": False, "error": str(e)}

    async def _try_git_apply(self, diff: str) -> dict | None:
        """Try to apply patch via git. Returns result dict, or None if git unavailable."""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".patch", delete=False, newline="\n",
            ) as tmp:
                tmp.write(diff)
                tmp_path = tmp.name

            git_flags = ["--no-index", "--ignore-whitespace", "--unidiff-zero", "--inaccurate-eof"]

            # Dry-run check
            proc = await asyncio.create_subprocess_exec(
                "git", "apply", "--check", *git_flags, tmp_path,
                cwd=self._project_root,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode != 0:
                os.unlink(tmp_path)
                err = stderr.decode("utf-8", errors="replace")
                return {"success": False, "error": f"git check: {err}"}

            # Apply
            proc = await asyncio.create_subprocess_exec(
                "git", "apply", *git_flags, tmp_path,
                cwd=self._project_root,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            os.unlink(tmp_path)
            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")
                return {"success": False, "error": f"git apply: {err}"}

            return {"success": True}
        except FileNotFoundError:
            # git not installed
            return None
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def definition() -> dict:
        return {
            "name": "apply_patch",
            "description": "Apply a diff patch to a file. Creates .bak backup.",
            "input_schema": pydantic_to_input_schema(ApplyPatchArgs),
        }
