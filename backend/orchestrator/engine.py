"""
Orchestrator engine - wraps LangGraph state machine for incident resolution.
Implements IOrchestrator interface, delegates to LangGraph graph nodes.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from backend.shared.circuit_breaker import CostCircuitBreaker
from backend.shared.config import AppConfig, SentryMode
from backend.shared.interfaces import ILLMClient, IMemoryStore, IOrchestrator, IToolExecutor
from backend.shared.models import (
    Incident, IncidentSeverity, IncidentState,
    LogEvent, MemoryEntry, ToolCall,
)
from backend.orchestrator.graph import IncidentGraphBuilder, IncidentGraphState
from backend.shared.audit_log import ImmutableAuditLog
from backend.services.registry import ServiceRegistry

logger = logging.getLogger(__name__)

# --- #4: Resolved incidents list cap (FIFO) ---
MAX_RESOLVED_INCIDENTS = 100


class Orchestrator(IOrchestrator):
    """
    Core orchestrator that uses LangGraph for structured state transitions.

    The LangGraph graph handles:
      TRIAGE -> DIAGNOSIS -> REMEDIATION -> VERIFICATION -> RESOLVED/ESCALATED

    This class manages incident lifecycle and memory persistence.
    """

    def __init__(
        self,
        config: AppConfig,
        llm: ILLMClient,
        tools: IToolExecutor,
        memory: IMemoryStore,
        circuit_breaker: CostCircuitBreaker,
        audit_log: Optional[ImmutableAuditLog] = None,
    ):
        self._config = config
        self._llm = llm
        self._tools = tools
        self._memory = memory
        self._cb = circuit_breaker
        self._audit_log = audit_log
        self._active_incidents: dict[str, Incident] = {}
        self._resolved_incidents: list[Incident] = []

        # Load Service Awareness Layer — built from .env paths, no YAML needed
        self._service_registry = ServiceRegistry(config)
        if self._service_registry.has_context():
            fingerprint = self._service_registry.build_fingerprint()
            memory.system_fingerprint = fingerprint
            logger.info(f"System fingerprint: {fingerprint}")
        else:
            logger.warning("No service context configured — agents will operate without service awareness")

        # Build the LangGraph compiled graph
        builder = IncidentGraphBuilder(config, llm, tools, memory, circuit_breaker)
        self._graph = builder.build()

    async def handle_event(self, event: LogEvent) -> Optional[Incident]:
        """Process a log event through the LangGraph state machine."""
        if self._cb.is_tripped:
            logger.warning("Circuit breaker tripped - skipping event")
            return None

        incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        incident = Incident(
            id=incident_id,
            symptom=event.line_content,
            log_events=[event.to_dict()],
        )
        self._active_incidents[incident_id] = incident

        try:
            # Build service context from .env paths
            service_context = self._service_registry.build_prompt_context()

            # Run the LangGraph state machine
            initial_state: IncidentGraphState = {
                "incident": incident,
                "service_context": service_context,
                "tool_results": [],
                "tool_loop_count": 0,
            }

            # ainvoke runs the graph to completion
            final_state = await self._graph.ainvoke(initial_state)
            incident = final_state["incident"]

            # Update our tracking
            self._active_incidents[incident_id] = incident

            if incident.state == IncidentState.RESOLVED:
                await self._save_to_memory(incident)
                self._resolved_incidents.append(incident)
                # --- #4: FIFO cap on resolved list to prevent unbounded growth ---
                if len(self._resolved_incidents) > MAX_RESOLVED_INCIDENTS:
                    self._resolved_incidents = self._resolved_incidents[-MAX_RESOLVED_INCIDENTS:]
                del self._active_incidents[incident_id]
            elif incident.state == IncidentState.IDLE:
                del self._active_incidents[incident_id]

            logger.info(
                f"Incident {incident_id} completed: state={incident.state.value}, "
                f"root_cause={incident.root_cause[:80] if incident.root_cause else 'N/A'}"
            )

        except Exception as e:
            logger.error(f"Orchestrator error for {incident_id}: {e}")
            incident.state = IncidentState.ESCALATED

        return incident

    async def _save_to_memory(self, incident: Incident) -> None:
        """Save resolved incident to long-term memory."""
        entry = MemoryEntry(
            id=incident.id,
            symptom=incident.symptom,
            root_cause=incident.root_cause or "Unknown",
            fix=incident.fix_applied or "None",
            vectors=incident.vectors or incident.symptom.lower().split()[:5],
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        await self._memory.save(entry)

        count = await self._memory.get_count()
        if count > self._config.memory.max_incidents_before_compaction:
            logger.info("Memory compaction threshold reached")

    async def get_active_incidents(self) -> list[Incident]:
        return list(self._active_incidents.values())

    async def get_status(self) -> dict:
        return {
            "active_incidents": len(self._active_incidents),
            "resolved_total": len(self._resolved_incidents),
            "circuit_breaker": self._cb.get_status(),
            "mode": self._config.security.mode.value,
        }
