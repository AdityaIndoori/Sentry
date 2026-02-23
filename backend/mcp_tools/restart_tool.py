"""
Restart service tool - executes the operator-configured restart command.

The restart command is read from the SERVICE_RESTART_CMD environment variable.
This makes Sentry service-agnostic — the operator configures exactly how to
restart the monitored service (docker restart, systemctl, supervisorctl, etc.).

Rate-limited: max 1 restart per cooldown period (default 10 minutes).
"""

import asyncio
import logging
import os

from backend.shared.circuit_breaker import RateLimiter
from backend.shared.security import SecurityGuard
from backend.mcp_tools.tool_schemas import RestartServiceArgs, pydantic_to_input_schema

logger = logging.getLogger(__name__)


class RestartServiceTool:
    """Execute the configured restart command with rate limiting."""

    def __init__(
        self,
        security: SecurityGuard,
        rate_limiter: RateLimiter,
        cooldown_seconds: int = 600,
    ):
        self._security = security
        self._rate_limiter = rate_limiter
        self._cooldown = cooldown_seconds

    async def execute(self) -> dict:
        restart_cmd = os.environ.get("SERVICE_RESTART_CMD", "").strip()
        if not restart_cmd:
            return {
                "success": False,
                "error": "SERVICE_RESTART_CMD not configured. "
                         "Set it in .env to the command that restarts the monitored service "
                         "(e.g. 'docker restart shopapi').",
            }

        if self._security.is_audit_mode():
            logger.info(f"[AUDIT] Would run restart: {restart_cmd}")
            return {
                "success": True,
                "output": f"[AUDIT MODE] Restart logged: {restart_cmd}",
                "audit_only": True,
            }

        key = "restart:service"
        if not self._rate_limiter.is_allowed(key, self._cooldown):
            remaining = self._rate_limiter.get_remaining(key, self._cooldown)
            return {
                "success": False,
                "error": f"Rate limited. Wait {remaining:.0f}s",
            }

        try:
            proc = await asyncio.create_subprocess_shell(
                restart_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=30
            )
            self._rate_limiter.record(key)

            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")
                return {"success": False, "error": f"Restart failed: {err}"}

            output = stdout.decode("utf-8", errors="replace")
            logger.info(f"Service restarted via: {restart_cmd}")
            return {"success": True, "output": f"Restarted service ({restart_cmd})"}
        except asyncio.TimeoutError:
            return {"success": False, "error": "Restart timed out (30s)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def definition() -> dict:
        return {
            "name": "restart_service",
            "description": (
                "Restart the monitored service using the operator-configured command. "
                "No parameters needed — the restart command is set in the environment. "
                "Rate limited to 1 restart per 10 minutes."
            ),
            "input_schema": pydantic_to_input_schema(RestartServiceArgs),
        }
