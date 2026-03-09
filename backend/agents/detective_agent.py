"""
Detective Agent - Deep investigation using high-effort thinking.

Responsibilities:
- Investigate root cause using read-only tools
- Iterative tool loop: read files, grep, run diagnostics
- Uses adaptive thinking with effort="high" for deep reasoning

Tools: read_file, grep_search, fetch_docs, run_diagnostics
"""

import logging
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.shared.vault import AgentRole, IVault
from backend.shared.ai_gateway import AIGateway
from backend.shared.agent_throttle import AgentThrottle
from backend.shared.tool_registry import TrustedToolRegistry
from backend.shared.models import Incident
from backend.shared.prompts import DIAGNOSIS_SYSTEM_PROMPT as DETECTIVE_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

MAX_TOOL_LOOPS = 8


class DetectiveAgent(BaseAgent):
    """
    Deep-investigation agent using high-effort adaptive thinking.
    Has read-only tool access for file inspection and diagnostics.
    """

    def __init__(
        self,
        vault: IVault,
        llm: Any,
        tools: Any,
        registry: TrustedToolRegistry,
        gateway: AIGateway,
        throttle: AgentThrottle,
        audit_log=None,
    ):
        super().__init__(vault, AgentRole.DETECTIVE, gateway, audit_log=audit_log,
                         llm=llm, tools=tools)
        self._registry = registry
        self._throttle = throttle

    async def run(self, incident: Incident, service_context: str = "") -> dict:
        """
        Investigate incident root cause.
        Returns: {"root_cause": str, "recommended_fix": str, "tool_results": list,
                  "input_tokens": int, "output_tokens": int, "activities": list}
        """
        self._activities = []
        self._call_count = 0
        cred = self._get_credential(scope="llm_call", ttl=120)
        tool_results = []
        total_input_tokens = 0
        total_output_tokens = 0

        try:
            safe_symptom = self._scan_input(incident.symptom)
            svc_text = ""
            if service_context:
                svc_text = f"\n\n{service_context}\n"
            messages = [
                f"Investigate this incident:\n\nSymptom: {safe_symptom}\n"
                f"Triage result: {incident.triage_result or 'N/A'}"
                f"{svc_text}"
            ]

            for loop_idx in range(MAX_TOOL_LOOPS):
                if not self._throttle.is_allowed(self.agent_id, "llm_call"):
                    logger.warning(f"Detective {self.agent_id} throttled at loop {loop_idx}")
                    self._log_activity("INFO", f"Throttled at loop {loop_idx}")
                    break

                full_prompt = f"{DETECTIVE_SYSTEM_PROMPT}\n\n" + "\n\n".join(messages)
                tool_defs = self._get_tool_definitions(category="read_only")

                response = await self._call_llm(
                    prompt=full_prompt, effort="high", tools=tool_defs,
                )
                total_input_tokens += response.get("input_tokens", 0)
                total_output_tokens += response.get("output_tokens", 0)

                text = response.get("text", "")
                tool_calls = response.get("tool_calls", [])

                if not tool_calls:
                    result = self._parse_using_schema(text)
                    result["tool_results"] = [
                        tr if isinstance(tr, dict) else {"output": str(tr)}
                        for tr in tool_results
                    ]
                    result["input_tokens"] = total_input_tokens
                    result["output_tokens"] = total_output_tokens
                    result["activities"] = self._activities
                    return result

                for tc in tool_calls:
                    tool_name = tc.get("name", "")
                    tool_args = tc.get("arguments", {})

                    if not self._registry.is_allowed(tool_name, AgentRole.DETECTIVE):
                        msg = f"BLOCKED: Tool '{tool_name}' not in Detective's allowlist"
                        logger.warning(msg)
                        messages.append(f"Tool error: {msg}")
                        continue

                    if not self._throttle.is_allowed(self.agent_id, "tool_call"):
                        messages.append("Tool error: Throttle limit reached")
                        break

                    try:
                        result = await self._call_tool(tool_name, tool_args)
                        safe_output = self._scan_and_redact_output(result.output)
                        self._audit(
                            "tool_executed",
                            f"tool={tool_name}, args={tool_args}",
                            f"success={result.success}",
                            metadata={"tool": tool_name, "success": result.success, "incident_id": incident.id},
                        )
                        tool_results.append({
                            "tool": tool_name,
                            "args": tool_args,
                            "output": safe_output[:2000],
                            "success": result.success,
                        })
                        messages.append(
                            f"Tool result ({tool_name}): {safe_output[:2000]}"
                        )
                    except Exception as e:
                        messages.append(f"Tool error ({tool_name}): {str(e)}")

                # Cap total prompt size to prevent token explosion
                full_text = "\n\n".join(messages)
                if len(full_text) > 50000:
                    messages = [messages[0]] + messages[-5:]

            return {
                "root_cause": "Investigation inconclusive after max tool loops",
                "recommended_fix": "Manual investigation required",
                "tool_results": tool_results,
                "input_tokens": total_input_tokens,
                "output_tokens": total_output_tokens,
                "activities": self._activities,
            }

        finally:
            self._vault.revoke_credential(cred.credential_id)

    def _parse_using_schema(self, text: str) -> dict:
        """Parse using the canonical DiagnosisResult schema (single source of truth)."""
        from backend.orchestrator.schemas import DiagnosisResult
        diagnosis = DiagnosisResult.parse_safe(text)
        return {
            "root_cause": diagnosis.root_cause,
            "recommended_fix": diagnosis.recommended_fix,
            "raw_text": text,
        }
