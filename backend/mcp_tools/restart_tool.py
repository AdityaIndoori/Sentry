"""
Restart service tool - rate-limited service restart.
Max 1 restart per 10 minutes per service.
"""

import asyncio
import logging
import re

from backend.shared.circuit_breaker import RateLimiter
from backend.shared.security import SecurityGuard

logger = logging.getLogger(__name__)

SAFE_SERVICE_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]+$")


class RestartServiceTool:
    """Restart a system service with rate limiting."""

    def __init__(
        self,
        security: SecurityGuard,
        rate_limiter: RateLimiter,
        cooldown_seconds: int = 600,
    ):
        self._security = security
        self._rate_limiter = rate_limiter
        self._cooldown = cooldown_seconds

    async def execute(self, service_name: str) -> dict:
        if not SAFE_SERVICE_PATTERN.match(service_name):
            return {
                "success": False,
                "error": "Invalid service name format",
            }

        if self._security.is_audit_mode():
            logger.info(f"[AUDIT] Would restart: {service_name}")
            return {
                "success": True,
                "output": f"[AUDIT MODE] Restart logged: {service_name}",
                "audit_only": True,
            }

        key = f"restart:{service_name}"
        if not self._rate_limiter.is_allowed(key, self._cooldown):
            remaining = self._rate_limiter.get_remaining(key, self._cooldown)
            return {
                "success": False,
                "error": f"Rate limited. Wait {remaining:.0f}s",
            }

        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl", "restart", service_name,
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
            logger.info(f"Service restarted: {service_name}")
            return {"success": True, "output": f"Restarted {service_name}"}
        except asyncio.TimeoutError:
            return {"success": False, "error": "Restart timed out (30s)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def definition() -> dict:
        return {
            "name": "restart_service",
            "description": "Restart a system service. Rate limited to 1/10min.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "service_name": {
                        "type": "string",
                        "description": "Name of the service to restart",
                    }
                },
                "required": ["service_name"],
            },
        }
