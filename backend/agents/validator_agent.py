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
from backend.shared.prompts import VERIFICATION_SYSTEM_PROMPT as VALIDATOR_SYSTEM_PROMPT

logger = logging.getLogger(__name__)


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
            return self._parse_using_schema(text)

        finally:
            self._vault.revoke_credential(cred.credential_id)

    def _parse_using_schema(self, text: str) -> dict:
        """Parse using the canonical VerificationResult schema (single source of truth)."""
        from backend.orchestrator.schemas import VerificationResult
        verification = VerificationResult.parse_safe(text)
        return {
            "resolved": verification.resolved,
            "reason": verification.reason,
            "raw_text": text,
        }
