"""
Triage Agent - Fast classification using low-effort thinking.

Responsibilities:
- Classify incident severity (low/medium/high/critical)
- Determine verdict: INVESTIGATE or FALSE_POSITIVE
- Uses adaptive thinking with effort="low" for fast pattern matching

Tools: NONE (triage is analysis-only, no tool access)
"""

import logging
import re
from typing import Any, Optional

from backend.agents.base_agent import BaseAgent
from backend.shared.vault import AgentRole, IVault
from backend.shared.ai_gateway import AIGateway
from backend.shared.models import Incident, MemoryEntry

logger = logging.getLogger(__name__)

TRIAGE_SYSTEM_PROMPT = """You are the Triage Agent for Claude Sentry, a self-healing server monitor.

Your ONLY job is to classify incoming error logs. You must respond with EXACTLY this format:

SEVERITY: <low|medium|high|critical>
VERDICT: <INVESTIGATE|FALSE_POSITIVE>
SUMMARY: <one-line description of the issue>

Rules:
- SEVERITY low: Informational, transient errors (e.g., timeout retries that succeeded)
- SEVERITY medium: Service degradation but not down
- SEVERITY high: Service partially down or data at risk
- SEVERITY critical: Complete outage or data loss imminent
- VERDICT INVESTIGATE: This needs deeper analysis
- VERDICT FALSE_POSITIVE: This is noise, ignore it

You have access to past incident history for pattern matching.
Be fast and decisive. Do NOT explain your reasoning at length."""


class TriageAgent(BaseAgent):
    """
    Fast-classifier agent using low-effort adaptive thinking.
    No tools - pure analysis of the log snippet + memory hints.
    """

    def __init__(self, vault: IVault, llm: Any, gateway: AIGateway):
        super().__init__(vault, AgentRole.TRIAGE, gateway)
        self._llm = llm

    async def run(
        self, incident: Incident, memory_hints: list[dict] = None
    ) -> dict:
        """
        Classify the incident.
        Returns: {"severity": str, "verdict": str, "summary": str}
        """
        # Get JIT credential for this LLM call
        cred = self._get_credential(scope="llm_call", ttl=30)

        try:
            # Scan the input through AI Gateway
            safe_symptom = self._scan_input(incident.symptom)

            # Build context
            memory_context = ""
            if memory_hints:
                memory_context = "\n\nPast similar incidents:\n"
                for hint in memory_hints[:5]:
                    memory_context += (
                        f"- {hint.get('symptom', 'N/A')} -> "
                        f"Root cause: {hint.get('root_cause', 'N/A')}\n"
                    )

            user_message = (
                f"Classify this error:\n\n{safe_symptom}"
                f"{memory_context}"
            )

            # Bug fix #1: ILLMClient.analyze() signature is (prompt, effort, tools).
            # Combine system prompt + user message into a single prompt string.
            full_prompt = f"{TRIAGE_SYSTEM_PROMPT}\n\n{user_message}"
            response = await self._llm.analyze(
                prompt=full_prompt,
                effort="low",
            )

            text = response.get("text", "")
            return self._parse_response(text)

        finally:
            # Always revoke credential after use
            self._vault.revoke_credential(cred.credential_id)

    def _parse_response(self, text: str) -> dict:
        """Parse the structured triage response."""
        result = {
            "severity": "medium",
            "verdict": "INVESTIGATE",
            "summary": "Unable to parse triage response",
            "raw_text": text,
        }

        # Parse SEVERITY
        sev_match = re.search(r"SEVERITY:\s*(low|medium|high|critical)", text, re.IGNORECASE)
        if sev_match:
            result["severity"] = sev_match.group(1).lower()

        # Parse VERDICT
        verdict_match = re.search(r"VERDICT:\s*(INVESTIGATE|FALSE_POSITIVE)", text, re.IGNORECASE)
        if verdict_match:
            result["verdict"] = verdict_match.group(1).upper()

        # Parse SUMMARY
        summary_match = re.search(r"SUMMARY:\s*(.+)", text)
        if summary_match:
            result["summary"] = summary_match.group(1).strip()

        return result
