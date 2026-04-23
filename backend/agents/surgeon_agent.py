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
from backend.shared.agent_throttle import AgentThrottle
from backend.shared.ai_gateway import AIGateway
from backend.shared.interfaces import IAuditLog
from backend.shared.models import Incident
from backend.shared.prompts import REMEDIATION_SYSTEM_PROMPT as SURGEON_SYSTEM_PROMPT
from backend.shared.tool_registry import TrustedToolRegistry
from backend.shared.vault import AgentRole, IVault

logger = logging.getLogger(__name__)


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
        audit_log: IAuditLog | None = None,
    ) -> None:
        super().__init__(vault, AgentRole.SURGEON, gateway, audit_log=audit_log,
                         llm=llm, tools=tools)
        self._registry = registry
        self._throttle = throttle
        self._config = config

    async def run(
        self,
        incident: Incident,
        tool_results_context: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Propose and optionally apply a fix.
        Returns: {"fix_description": str, "fix_applied": bool, "tool_results": list,
                  "tools_used": list, "input_tokens": int, "output_tokens": int,
                  "activities": list}
        """
        self._activities = []
        self._call_count = 0
        cred = self._get_credential(scope="llm_call", ttl=90)
        tool_results: list[dict[str, Any]] = []
        tools_used: list[str] = []
        total_input_tokens = 0
        total_output_tokens = 0
        max_remediation_loops = 4

        try:
            diag_context = ""
            if tool_results_context:
                diag_context = "\n\nCode investigated during diagnosis:\n"
                for r in tool_results_context[-15:]:
                    diag_context += f"  {r}\n"

            context = (
                f"Root cause: {incident.root_cause or 'Unknown'}\n"
                f"Symptom: {incident.symptom}\n"
                f"Mode: {self._config.security.mode.value}"
                f"{diag_context}"
            )

            full_prompt = f"{SURGEON_SYSTEM_PROMPT}\n\nApply a fix for this incident:\n\n{context}"
            tool_defs = self._get_tool_definitions(category="remediation")

            for _rem_loop in range(max_remediation_loops):
                response = await self._call_llm(
                    prompt=full_prompt, effort="medium", tools=tool_defs,
                )
                total_input_tokens += response.get("input_tokens", 0)
                total_output_tokens += response.get("output_tokens", 0)

                text = response.get("text", "")
                tool_calls = response.get("tool_calls", [])

                if not tool_calls:
                    break

                for tc in tool_calls:
                    tool_name = tc.get("name", "")
                    tool_args = tc.get("arguments", {})

                    if not self._registry.is_allowed(tool_name, AgentRole.SURGEON):
                        logger.warning(f"BLOCKED: Tool '{tool_name}' not in Surgeon's allowlist")
                        continue

                    if not self._throttle.is_allowed(self.agent_id, "tool_call"):
                        logger.warning(f"Surgeon {self.agent_id} throttled")
                        break

                    try:
                        result = await self._call_tool(tool_name, tool_args)
                        tools_used.append(tool_name)
                        result_text = result.output or result.error or ""
                        full_prompt += f"\n\nTool {tool_name} result: {result_text[:2000]}"
                        tool_results.append({
                            "tool": tool_name,
                            "success": result.success,
                            "output": result.output[:500],
                            "audit_only": result.audit_only,
                        })
                        self._audit(
                            "tool_executed",
                            f"tool={tool_name}, args={tool_args}",
                            f"success={result.success}",
                            metadata={"tool": tool_name, "success": result.success, "incident_id": incident.id},
                        )
                    except Exception as e:
                        tool_results.append({
                            "tool": tool_name,
                            "success": False,
                            "output": str(e),
                        })

                if len(full_prompt) > 50000:
                    full_prompt = full_prompt[:25000] + "\n\n[...truncated...]\n\n" + full_prompt[-20000:]

            parsed = self._parse_response(text)
            return {
                "fix_description": parsed.get("fix_proposed", text[:200]),
                "fix_details": parsed.get("fix_details", ""),
                "fix_applied": any(tr.get("success") for tr in tool_results),
                "tool_results": tool_results,
                "tools_used": tools_used,
                "input_tokens": total_input_tokens,
                "output_tokens": total_output_tokens,
                "activities": self._activities,
            }

        finally:
            self._vault.revoke_credential(cred.credential_id)

    def _parse_response(self, text: str) -> dict[str, Any]:
        result: dict[str, Any] = {}
        match = re.search(r"FIX\s*PROPOSED:\s*(.+?)(?:\n|$)", text, re.IGNORECASE)
        if match:
            result["fix_proposed"] = match.group(1).strip()
        match = re.search(r"FIX\s*DETAILS:\s*(.+)", text, re.IGNORECASE | re.DOTALL)
        if match:
            result["fix_details"] = match.group(1).strip()[:1000]
        return result
