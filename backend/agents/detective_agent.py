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
from backend.shared.models import Incident, ToolCall, ToolResult

logger = logging.getLogger(__name__)

MAX_TOOL_LOOPS = 8

DETECTIVE_SYSTEM_PROMPT = """You are the Detective Agent for Claude Sentry, a self-healing server monitor.

Your job is to investigate the ROOT CAUSE of an incident. You have access to read-only tools:
- read_file(path): Read a file on the server
- grep_search(query, path): Search files for a pattern
- run_diagnostics(command): Run safe diagnostic commands (ps, netstat, curl, tail, etc.)

Investigate systematically:
1. Read relevant configuration and code files
2. Check system state with diagnostics
3. Correlate findings

When you have found the root cause, respond with EXACTLY this format:
ROOT CAUSE: <clear description of the root cause>
RECOMMENDED FIX: <specific fix to apply>

If you need to use a tool, respond with a tool_call. Do NOT guess - investigate first."""


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
    ):
        super().__init__(vault, AgentRole.DETECTIVE, gateway)
        self._llm = llm
        self._tools = tools
        self._registry = registry
        self._throttle = throttle

    async def run(self, incident: Incident) -> dict:
        """
        Investigate incident root cause.
        Returns: {"root_cause": str, "recommended_fix": str, "tool_results": list}
        """
        cred = self._get_credential(scope="llm_call", ttl=120)
        tool_results = []

        try:
            safe_symptom = self._scan_input(incident.symptom)
            messages = [
                f"Investigate this incident:\n\nSymptom: {safe_symptom}\n"
                f"Triage result: {incident.triage_result or 'N/A'}"
            ]

            for loop_idx in range(MAX_TOOL_LOOPS):
                # Check throttle
                if not self._throttle.is_allowed(self.agent_id, "llm_call"):
                    logger.warning(f"Detective {self.agent_id} throttled at loop {loop_idx}")
                    break

                # Bug fix #1: ILLMClient.analyze() signature is (prompt, effort, tools).
                # Combine system prompt + messages into a single prompt string.
                full_prompt = f"{DETECTIVE_SYSTEM_PROMPT}\n\n" + "\n\n".join(messages)
                # Get tool definitions for the LLM to use
                tool_defs = self._tools.get_tool_definitions() if hasattr(self._tools, 'get_tool_definitions') else None
                response = await self._llm.analyze(
                    prompt=full_prompt,
                    effort="high",
                    tools=tool_defs,
                )

                text = response.get("text", "")
                tool_calls = response.get("tool_calls", [])

                # If no tool calls, we have a final answer
                if not tool_calls:
                    result = self._parse_response(text)
                    result["tool_results"] = [
                        tr if isinstance(tr, dict) else {"output": str(tr)}
                        for tr in tool_results
                    ]
                    return result

                # Execute tool calls
                for tc in tool_calls:
                    tool_name = tc.get("name", "")
                    tool_args = tc.get("arguments", {})

                    # Check tool registry
                    if not self._registry.is_allowed(tool_name, AgentRole.DETECTIVE):
                        msg = f"BLOCKED: Tool '{tool_name}' not in Detective's allowlist"
                        logger.warning(msg)
                        messages.append(f"Tool error: {msg}")
                        continue

                    # Check throttle for tool use
                    if not self._throttle.is_allowed(self.agent_id, "tool_call"):
                        messages.append("Tool error: Throttle limit reached")
                        break

                    # Bug fix #2: IToolExecutor.execute() takes a single ToolCall object,
                    # not two separate arguments.
                    try:
                        call = ToolCall(tool_name=tool_name, arguments=tool_args)
                        result = await self._tools.execute(call)
                        safe_output = self._scan_and_redact_output(result.output)
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

            # If we exhausted loops without a final answer
            return {
                "root_cause": "Investigation inconclusive after max tool loops",
                "recommended_fix": "Manual investigation required",
                "tool_results": tool_results,
            }

        finally:
            self._vault.revoke_credential(cred.credential_id)

    def _parse_response(self, text: str) -> dict:
        """Parse the detective's diagnosis response."""
        import re
        result = {
            "root_cause": "Unknown",
            "recommended_fix": "None",
            "raw_text": text,
        }

        rc_match = re.search(r"ROOT\s*CAUSE:\s*(.+?)(?:\n|$)", text, re.IGNORECASE)
        if rc_match:
            result["root_cause"] = rc_match.group(1).strip()

        fix_match = re.search(r"RECOMMENDED\s*FIX:\s*(.+?)(?:\n|$)", text, re.IGNORECASE)
        if fix_match:
            result["recommended_fix"] = fix_match.group(1).strip()

        return result
