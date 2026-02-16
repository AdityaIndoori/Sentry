"""
Active MCP tools - Operations that modify system state.
Requires ACTIVE mode. In AUDIT mode, logs intent only.
"""

import asyncio
import logging
import os
import shutil

from backend.shared.circuit_breaker import RateLimiter
from backend.shared.security import SecurityGuard

logger = logging.getLogger(__name__)


class RunDiagnosticsTool:
    """Run whitelisted diagnostic commands."""

    def __init__(self, security: SecurityGuard):
        self._security = security

    async def execute(self, command: str) -> dict:
        sanitized = self._security.sanitize_input(command)
        if not self._security.validate_command(sanitized):
            return {
                "success": False,
                "error": f"Command not in whitelist: {sanitized}",
            }

        if self._security.is_audit_mode():
            logger.info(f"[AUDIT] Would run: {sanitized}")
            return {
                "success": True,
                "output": f"[AUDIT MODE] Command logged: {sanitized}",
                "audit_only": True,
            }

        try:
            proc = await asyncio.create_subprocess_shell(
                sanitized,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=30
            )
            output = stdout.decode("utf-8", errors="replace")
            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")
                output += f"\nSTDERR: {err}"
            return {"success": proc.returncode == 0, "output": output[:5000]}
        except asyncio.TimeoutError:
            return {"success": False, "error": "Command timed out (30s)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def definition() -> dict:
        return {
            "name": "run_diagnostics",
            "description": "Run a whitelisted diagnostic command.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Diagnostic command to run",
                    }
                },
                "required": ["command"],
            },
        }
