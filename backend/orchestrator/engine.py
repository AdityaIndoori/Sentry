"""
Orchestrator engine — wraps LangGraph state machine for incident resolution.
Implements IOrchestrator interface, delegates to LangGraph graph nodes.

P1.3 upgrades
-------------
* **Fingerprint dedup**: every incoming event is normalized to
  ``sha256(source|pattern|line)`` and compared against recent incidents.
  When ``incident_repo`` is wired (P1.2 Postgres path) we consult the DB
  with a configurable rolling window; otherwise we use an in-memory
  fallback keyed on the same fingerprint. Dedup hits short-circuit
  ``handle_event`` → no agent loop, no LLM spend, no new incident row.
* **Graph timeout**: ``self._graph.ainvoke(...)`` is wrapped in
  ``asyncio.wait_for(..., timeout=settings.orchestrator_timeout_seconds)``.
  A runaway LLM or a stuck tool loop now terminates cleanly with
  ``IncidentState.ESCALATED`` instead of holding the caller forever.
* **Persistence hook**: when ``incident_repo`` is present, every state
  transition gets persisted (create, terminal). The legacy
  ``_active_incidents`` / ``_resolved_incidents`` in-memory views are
  preserved so existing unit tests keep working.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import deque
from datetime import UTC, datetime
from typing import Any

from backend.orchestrator.graph import IncidentGraphBuilder, IncidentGraphState
from backend.services.registry import ServiceRegistry
from backend.shared.agent_throttle import AgentThrottle
from backend.shared.ai_gateway import AIGateway
from backend.shared.audit_log import ImmutableAuditLog
from backend.shared.circuit_breaker import CostCircuitBreaker
from backend.shared.config import AppConfig
from backend.shared.interfaces import ILLMClient, IMemoryStore, IOrchestrator, IToolExecutor
from backend.shared.metrics import inc_circuit_breaker_trip, inc_incident
from backend.shared.models import (
    Incident,
    IncidentState,
    LogEvent,
    MemoryEntry,
)
from backend.shared.observability import get_telemetry
from backend.shared.tool_registry import TrustedToolRegistry
from backend.shared.vault import IVault

logger = logging.getLogger(__name__)

# --- #4: Resolved incidents list cap (FIFO) ---
MAX_RESOLVED_INCIDENTS = 100

# --- P1.3: orchestrator runtime knobs ---
DEFAULT_ORCH_TIMEOUT_SECONDS = 300
DEFAULT_DEDUP_WINDOW_SECONDS = 60


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
        audit_log: ImmutableAuditLog | None = None,
        vault: IVault | None = None,
        gateway: AIGateway | None = None,
        throttle: AgentThrottle | None = None,
        registry: TrustedToolRegistry | None = None,
        *,
        incident_repo: Any | None = None,  # IncidentRepository; optional keyword
        orchestrator_timeout_seconds: int = DEFAULT_ORCH_TIMEOUT_SECONDS,
        dedup_window_seconds: int = DEFAULT_DEDUP_WINDOW_SECONDS,
        broadcaster: Any | None = None,  # P2.4: IncidentBroadcaster; optional
    ) -> None:
        self._config = config
        self._llm = llm
        self._tools = tools
        self._memory = memory
        self._cb = circuit_breaker
        self._audit_log = audit_log
        self._vault = vault
        self._gateway = gateway
        self._throttle = throttle
        self._registry = registry
        self._incident_repo = incident_repo
        self._orch_timeout = orchestrator_timeout_seconds
        self._dedup_window = dedup_window_seconds
        self._broadcaster = broadcaster
        self._active_incidents: dict[str, Incident] = {}
        # Use deque with maxlen so FIFO trimming is O(1) and correct by construction.
        self._resolved_incidents: deque[Incident] = deque(maxlen=MAX_RESOLVED_INCIDENTS)

        # --- P1.3 in-memory dedup cache ---
        # Maps fingerprint -> monotonic-clock timestamp of last accepted event.
        # Serves the `incident_repo is None` path and is trimmed lazily on
        # every `handle_event` to keep memory bounded.
        self._recent_fingerprints: dict[str, float] = {}
        self._dedup_lock = asyncio.Lock()

        # Load Service Awareness Layer — built from .env paths, no YAML needed
        self._service_registry = ServiceRegistry(config)
        if self._service_registry.has_context():
            fingerprint = self._service_registry.build_fingerprint()
            # ``IMemoryStore`` doesn't declare ``system_fingerprint`` on the
            # ABC because only one implementer (the Postgres-backed repo
            # via ``PostgresMemoryRepo``) supports it. Adding it to the ABC
            # would force every fake / in-memory test double to implement
            # it too. Use ``setattr`` so strict mypy doesn't flag the
            # attribute access while runtime duck-typing is preserved.
            setattr(memory, "system_fingerprint", fingerprint)  # noqa: B010
            logger.info(f"System fingerprint: {fingerprint}")
        else:
            logger.warning("No service context configured — agents will operate without service awareness")

        # Build the LangGraph compiled graph — pass Zero Trust deps for agent delegation
        builder = IncidentGraphBuilder(
            config, llm, tools, memory, circuit_breaker,
            vault=vault, gateway=gateway, audit_log=audit_log,
            throttle=throttle, registry=registry,
        )
        self._graph = builder.build()

    # ------------------------------------------------------------------
    # P1.3 fingerprint dedup
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_event_fingerprint(event: LogEvent) -> str:
        """Compute the dedup fingerprint for a log event.

        Mirrors ``backend.persistence.repositories.incident_repo.compute_fingerprint``;
        we re-implement the handful of lines here so the orchestrator's
        in-memory path doesn't have to import the persistence package
        (which pulls in SQLAlchemy for no benefit when DATABASE_URL is
        empty).
        """
        import hashlib
        src = event.source_file or ""
        pat = event.matched_pattern or ""
        line = (event.line_content or "").strip()
        material = f"{src}|{pat}|{line}".encode("utf-8", errors="replace")
        return hashlib.sha256(material).hexdigest()

    async def _is_duplicate(self, fingerprint: str) -> bool:
        """Return True if this fingerprint has been seen within the dedup window.

        Design
        ------
        We check the in-memory ``_recent_fingerprints`` cache under a
        single async lock *first*. This gives us correct dedup under
        burst / log-storm concurrency (50 identical events that arrive
        in the same second must collapse to one incident) without
        needing the DB to serialize them — two concurrent
        ``dedupe_fingerprint`` queries against the repo would both
        return False before either observed the other's insert.

        When ``incident_repo`` is wired we additionally consult it
        *after* the cache miss, which catches process-restart cases
        where the in-memory cache is empty but the DB still has a
        row inside the window.

        Either way the window is ``self._dedup_window`` seconds.
        """
        if not fingerprint:
            return False

        now = time.monotonic()
        async with self._dedup_lock:
            # Opportunistic eviction so the dict doesn't grow forever.
            cutoff = now - (self._dedup_window * 2)
            if self._recent_fingerprints:
                stale = [fp for fp, ts in self._recent_fingerprints.items() if ts < cutoff]
                for fp in stale:
                    self._recent_fingerprints.pop(fp, None)

            last = self._recent_fingerprints.get(fingerprint)
            if last is not None and (now - last) < self._dedup_window:
                return True
            # Record this observation synchronously under the lock so
            # concurrent callers (asyncio.gather of 50 identical events)
            # that race in after us all see the mark.
            self._recent_fingerprints[fingerprint] = now

        # Cache miss. Ask the persistent repo (if available) — this is
        # authoritative across process restarts.
        if self._incident_repo is not None:
            try:
                result = await self._incident_repo.dedupe_fingerprint(
                    fingerprint, window_seconds=self._dedup_window
                )
                return bool(result)
            except Exception:  # pragma: no cover
                logger.exception("dedup: incident_repo.dedupe_fingerprint failed")
                return False
        return False

    # ------------------------------------------------------------------
    # Main event handler
    # ------------------------------------------------------------------

    async def handle_event(self, event: LogEvent) -> Incident | None:
        """Process a log event through the LangGraph state machine.

        Terminal states (RESOLVED, IDLE, ESCALATED) are ALWAYS removed
        from the ``_active_incidents`` dict in the finally block — this
        prevents the ESCALATED-leak bug where failed incidents
        accumulated forever.

        P1.3 additions
        --------------
        * Fingerprint dedup short-circuits before any LLM spend.
        * ``asyncio.wait_for`` around the graph guards against hung
          agents.
        """
        # P2.3b-full: open a root span for the whole incident lifecycle.
        # The actual body runs inside _handle_event_impl so the span
        # scope covers every return path (including the dedup + cb
        # short-circuits) without having to hand-wrap each one.
        with get_telemetry().span(
            "orchestrator.handle_event",
            source=event.source_file or "",
            pattern=event.matched_pattern or "",
        ):
            return await self._handle_event_impl(event)

    async def _handle_event_impl(self, event: LogEvent) -> Incident | None:
        if self._cb.is_tripped:
            logger.warning("Circuit breaker tripped - skipping event")
            inc_circuit_breaker_trip()
            return None

        # --- P1.3: fingerprint dedup ---
        fingerprint = self._compute_event_fingerprint(event)
        if await self._is_duplicate(fingerprint):
            logger.info(
                "dedup: skipping event (fingerprint seen within %ds): %s",
                self._dedup_window, (event.line_content or "")[:80],
            )
            return None

        incident_id = f"INC-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        incident = Incident(
            id=incident_id,
            symptom=event.line_content,
            log_events=[event.to_dict()],
        )
        self._active_incidents[incident_id] = incident

        # --- P1.3: persist on creation (Postgres path only) ---
        if self._incident_repo is not None:
            try:
                await self._incident_repo.save(incident, fingerprint=fingerprint)
            except Exception:  # pragma: no cover
                logger.exception("incident_repo.save failed at creation")

        # --- P2.4: announce incident creation to live SSE subscribers ---
        self._broadcast("incident.created", incident)

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

            # --- P1.3: wrap in asyncio.wait_for ---
            # ainvoke runs the graph to completion; if it takes longer
            # than the configured timeout we escalate cleanly.
            try:
                final_state = await asyncio.wait_for(
                    self._graph.ainvoke(initial_state),
                    timeout=self._orch_timeout,
                )
            except TimeoutError:
                logger.error(
                    "Orchestrator timeout after %ds for %s — escalating",
                    self._orch_timeout, incident_id,
                )
                incident.state = IncidentState.ESCALATED
                if self._audit_log:
                    try:
                        self._audit_log.log_action(
                            agent_id="orchestrator",
                            action="orchestrator_timeout",
                            detail=f"incident={incident_id} timeout={self._orch_timeout}s",
                            result="escalated",
                        )
                    except Exception:  # pragma: no cover
                        logger.exception("audit log of timeout failed")
                # Skip the usual save-to-memory; proceed to finally.
                return incident

            incident = final_state["incident"]

            if incident.state == IncidentState.RESOLVED:
                await self._save_to_memory(incident)
                self._resolved_incidents.append(incident)

            logger.info(
                f"Incident {incident_id} completed: state={incident.state.value}, "
                f"root_cause={incident.root_cause[:80] if incident.root_cause else 'N/A'}"
            )

        except Exception as e:
            logger.exception(f"Orchestrator error for {incident_id}: {e}")
            incident.state = IncidentState.ESCALATED

        finally:
            # Bug fix: every terminal state must be removed from _active_incidents.
            # Previously only RESOLVED and IDLE were cleaned up; ESCALATED leaked
            # forever and bloated /api/status. Now all terminal states are removed
            # unconditionally — whether we got there by success, error, or escalation.
            self._active_incidents.pop(incident_id, None)

            # --- P1.3: persist the terminal transition ---
            if self._incident_repo is not None:
                try:
                    await self._incident_repo.save(incident, fingerprint=fingerprint)
                except Exception:  # pragma: no cover
                    logger.exception("incident_repo.save failed at terminal state")

            # --- P2.4: announce terminal state to live SSE subscribers ---
            # Done in the finally block so RESOLVED / IDLE / ESCALATED all
            # fire an event — including the path where an exception skipped
            # the happy-path return at the ``TimeoutError`` branch above.
            self._broadcast("incident.updated", incident)

            # --- P2.3b: Prometheus counter for OBS-02 ---
            # No-op when prometheus_client is not installed.
            try:
                inc_incident(incident.state.value)
            except Exception:  # pragma: no cover — defensive
                logger.exception("metrics: inc_incident failed")

        return incident

    # ------------------------------------------------------------------
    # P2.4 broadcast helper
    # ------------------------------------------------------------------

    def _broadcast(self, kind: str, incident: Incident) -> None:
        """Push an ``{kind, incident: <dict>}`` event to the broadcaster.

        Never raises; broadcasting is best-effort and must not block the
        orchestrator's hot path even if every SSE subscriber is wedged.
        """
        if self._broadcaster is None:
            return
        try:
            payload = {
                "kind": kind,
                "incident": incident.to_dict(),
                "ts": datetime.now(UTC).isoformat(),
            }
            self._broadcaster.publish_nowait(payload)
        except Exception:  # pragma: no cover — defensive
            logger.exception("broadcaster publish failed (kind=%s)", kind)

    async def _save_to_memory(self, incident: Incident) -> None:
        """Save resolved incident to long-term memory."""
        entry = MemoryEntry(
            id=incident.id,
            symptom=incident.symptom,
            root_cause=incident.root_cause or "Unknown",
            fix=incident.fix_applied or "None",
            vectors=incident.vectors or incident.symptom.lower().split()[:5],
            timestamp=datetime.now(UTC).isoformat(),
        )
        await self._memory.save(entry)

        count = await self._memory.get_count()
        if count > self._config.memory.max_incidents_before_compaction:
            logger.info("Memory compaction threshold reached")

    async def get_active_incidents(self) -> list[Incident]:
        return list(self._active_incidents.values())

    async def get_status(self) -> dict[str, Any]:
        return {
            "active_incidents": len(self._active_incidents),
            "resolved_total": len(self._resolved_incidents),
            "circuit_breaker": self._cb.get_status(),
            "mode": self._config.security.mode.value,
        }
