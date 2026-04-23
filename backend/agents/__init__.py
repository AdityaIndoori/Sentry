"""Multi-agent architecture: Triage, Detective, Surgeon, Validator.

Routing between agents is done deterministically by the LangGraph
StateGraph in `backend.orchestrator.graph`. There is no SupervisorAgent
— routing is pure functions inside the graph builder.
"""

__all__ = [
    "base_agent",
    "detective_agent",
    "surgeon_agent",
    "triage_agent",
    "validator_agent",
]
