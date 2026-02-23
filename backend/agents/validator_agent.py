"""
Validator Agent - Post-fix verification with disabled thinking.

Responsibilities:
- Verify that the fix actually resolved the issue
- Simple deterministic check (thinking disabled)
- Returns resolved=True/False

Tools: NONE (validation is analysis of fix results only)
"""

import logging
import re
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.shared.vault import AgentRole, IVault
from backend.shared.ai_gateway import AIGateway
from backend.shared.models import Incident

logger = logging.getLogger(__name__)

VALIDATOR_SYSTEM_PROMPT = """You are the Validator Agent for Sentry.

Your job is to verify whether a fix was successful.
Analyze the incident symptom, the applied fix, and any diagnostic output.

Respond with EXACTLY one line:
RESOLVED: <true|false>
REASON: <one-line explanation>

Be conservative. If you are not confident the fix resolved the issue, say false."""


class ValidatorAgent(BaseAgent):
    """
    Post-fix verification agent with minimal thinking overhead.
    No tools - pure analysis of fix results.
    """

    def __init__(self, vault: IVault, llm: Any, gateway: AIGateway, audit_log=None):
        super().__init__(vault, AgentRole.VALIDATOR, gateway, audit_log=audit_log)
        self._llm = llm

    async def run(self, incident: Incident) -> dict:
        """
        Verify fix was successful.
        Returns: {"resolved": bool, "reason": str}
        """
        cred = self._get_credential(scope="llm_call", ttl=30)

        try:
            context = (
                f"Symptom: {incident.symptom}\n"
                f"Root cause: {incident.root_cause or 'Unknown'}\n"
                f"Fix applied: {incident.fix_applied or 'None'}"
            )

            # Bug fix #1: ILLMClient.analyze() signature is (prompt, effort, tools).
            # Combine system prompt + user message into a single prompt string.
            full_prompt = f"{VALIDATOR_SYSTEM_PROMPT}\n\nVerify this fix:\n\n{context}"
            response = await self._llm.analyze(
                prompt=full_prompt,
                effort="disabled",
            )

            text = response.get("text", "")
            return self._parse_response(text)

        finally:
            self._vault.revoke_credential(cred.credential_id)

    def _parse_response(self, text: str) -> dict:
        result = {"resolved": False, "reason": "Unable to parse", "raw_text": text}

        resolved_match = re.search(r"RESOLVED:\s*(true|false)", text, re.IGNORECASE)
        if resolved_match:
            result["resolved"] = resolved_match.group(1).lower() == "true"

        reason_match = re.search(r"REASON:\s*(.+)", text, re.IGNORECASE)
        if reason_match:
            result["reason"] = reason_match.group(1).strip()
        else:
            # If we can't parse, check if the text seems positive
            lower = text.lower()
            if "resolved" in lower or "fixed" in lower or "successful" in lower:
                result["resolved"] = True
                result["reason"] = text[:200]

        return result
