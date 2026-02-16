"""
Supervisor Agent - Orchestrates the multi-agent workflow.

Routes incidents through: Triage -> Detective -> Surgeon -> Validator
Uses conditional edges to determine next step based on agent outputs.

The Supervisor itself has NO tool access and NO LLM access.
It is pure routing logic - deterministic and auditable.
"""

import logging
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.shared.vault import AgentRole, IVault
from backend.shared.ai_gateway import AIGateway
from backend.shared.models import Incident, IncidentState

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# ROUTING FUNCTIONS (Pure functions, testable independently)
# ═══════════════════════════════════════════════════════════════

def route_after_triage(state: dict) -> str:
    """Route based on triage verdict."""
    triage_result = state.get("triage_result", {})
    verdict = triage_result.get("verdict", "INVESTIGATE")

    if verdict == "FALSE_POSITIVE":
        return "end"
    return "detective"


def route_after_verification(state: dict) -> str:
    """Route based on verification result."""
    incident = state.get("incident")
    if not incident:
        return "end"

    if incident.state == IncidentState.RESOLVED:
        return "end"
    elif incident.state == IncidentState.ESCALATED:
        return "end"
    else:
        # Failed verification - retry investigation
        return "detective"


# ═══════════════════════════════════════════════════════════════
# SUPERVISOR AGENT
# ═══════════════════════════════════════════════════════════════

class SupervisorAgent(BaseAgent):
    """
    Orchestrator that routes incidents through the agent pipeline.

    The Supervisor:
    - Has NO LLM access (pure routing logic)
    - Has NO tool access
    - Makes deterministic routing decisions
    - Tracks incident state transitions
    """

    def __init__(self, vault: IVault, config: Any):
        super().__init__(vault, AgentRole.SUPERVISOR, AIGateway())
        self._config = config

    async def route(self, incident: Incident, phase_result: dict, current_phase: str) -> str:
        """
        Determine the next phase based on the current phase result.
        Returns: "triage", "detective", "surgeon", "validator", or "end"
        """
        if current_phase == "triage":
            state = {"triage_result": phase_result, "incident": incident}
            return route_after_triage(state)

        elif current_phase == "detective":
            # Detective found root cause -> go to surgeon
            if phase_result.get("root_cause") and phase_result["root_cause"] != "Unknown":
                return "surgeon"
            # Detective inconclusive -> escalate
            return "end"

        elif current_phase == "surgeon":
            # Surgeon applied fix -> validate
            return "validator"

        elif current_phase == "validator":
            state = {"incident": incident}
            return route_after_verification(state)

        return "end"
