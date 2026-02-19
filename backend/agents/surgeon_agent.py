"""
Surgeon Agent - Apply fixes using medium-effort thinking.

Responsibilities:
- Propose and apply fixes (apply_patch, restart_service)
- Respects AUDIT mode (log-only, no execution)
- Uses adaptive thinking with effort="medium"

Tools: apply_patch, restart_service (ACTIVE tools only)
"""

import logging
import re
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.shared.vault import AgentRole, IVault
from backend.shared.ai_gateway import AIGateway
from backend.shared.agent_throttle import AgentThrottle
from backend.shared.tool_registry import TrustedToolRegistry
from backend.shared.models import Incident, ToolCall

logger = logging.getLogger(__name__)

SURGEON_SYSTEM_PROMPT = """You are the Surgeon Agent for Claude Sentry, a self-healing server monitor.

You have been given a diagnosis with root cause and recommended fix.
Your job is to propose the EXACT fix to apply.

Available tools:
- apply_patch(diff, file_path): Apply a code patch (creates .bak backup automatically)
- restart_service(service_name): Restart a system service

Respond with EXACTLY this format:
FIX PROPOSED: <one-line description of the fix>
FIX DETAILS: <multi-line technical details if needed>

If you need to use a tool, respond with a tool_call.
NEVER apply destructive changes. Always prefer minimal, targeted patches."""


class SurgeonAgent(BaseAgent):
    """
    Remediation agent that applies fixes with medium-effort thinking.
    Has ACTIVE tool access (apply_patch, restart_service).
    Respects AUDIT mode.
    """

    def __init__(
        self,
        vault: IVault,
        llm: Any,
        tools: Any,
        registry: TrustedToolRegistry,
        gateway: AIGateway,
        throttle: AgentThrottle,
        config: Any,
    ):
        super().__init__(vault, AgentRole.SURGEON, gateway)
        self._llm = llm
        self._tools = tools
        self._registry = registry
        self._throttle = throttle
        self._config = config

    async def run(self, incident: Incident) -> dict:
        """
        Propose and optionally apply a fix.
        Returns: {"fix_description": str, "fix_applied": bool, "tool_results": list}
        """
        cred = self._get_credential(scope="llm_call", ttl=90)
        tool_results = []

        try:
            context = (
                f"Root cause: {incident.root_cause or 'Unknown'}\n"
                f"Symptom: {incident.symptom}\n"
                f"Mode: {self._config.security.mode.value}"
            )

            # Bug fix #1: ILLMClient.analyze() signature is (prompt, effort, tools).
            full_prompt = f"{SURGEON_SYSTEM_PROMPT}\n\nApply a fix for this incident:\n\n{context}"
            tool_defs = self._tools.get_tool_definitions() if hasattr(self._tools, 'get_tool_definitions') else None
            response = await self._llm.analyze(
                prompt=full_prompt,
                effort="medium",
                tools=tool_defs,
            )

            text = response.get("text", "")
            tool_calls = response.get("tool_calls", [])

            # Execute any tool calls
            for tc in tool_calls:
                tool_name = tc.get("name", "")
                tool_args = tc.get("arguments", {})

                if not self._registry.is_allowed(tool_name, AgentRole.SURGEON):
                    logger.warning(f"BLOCKED: Tool '{tool_name}' not in Surgeon's allowlist")
                    continue

                if not self._throttle.is_allowed(self.agent_id, "tool_call"):
                    logger.warning(f"Surgeon {self.agent_id} throttled")
                    break

                # Bug fix #2: IToolExecutor.execute() takes a single ToolCall object.
                try:
                    call = ToolCall(tool_name=tool_name, arguments=tool_args)
                    result = await self._tools.execute(call)
                    tool_results.append({
                        "tool": tool_name,
                        "success": result.success,
                        "output": result.output[:500],
                        "audit_only": result.audit_only,
                    })
                except Exception as e:
                    tool_results.append({
                        "tool": tool_name,
                        "success": False,
                        "output": str(e),
                    })

            parsed = self._parse_response(text)
            return {
                "fix_description": parsed.get("fix_proposed", text[:200]),
                "fix_details": parsed.get("fix_details", ""),
                "fix_applied": any(tr.get("success") for tr in tool_results),
                "tool_results": tool_results,
            }

        finally:
            self._vault.revoke_credential(cred.credential_id)

    def _parse_response(self, text: str) -> dict:
        result = {}
        match = re.search(r"FIX\s*PROPOSED:\s*(.+?)(?:\n|$)", text, re.IGNORECASE)
        if match:
            result["fix_proposed"] = match.group(1).strip()
        match = re.search(r"FIX\s*DETAILS:\s*(.+)", text, re.IGNORECASE | re.DOTALL)
        if match:
            result["fix_details"] = match.group(1).strip()[:1000]
        return result
