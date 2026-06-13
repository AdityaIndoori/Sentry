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

Effectiveness upgrades
----------------------
* **Normalized fingerprints**: dedup keys now hash a *normalized* log
  line (timestamps/PIDs/IPs/hex collapse to placeholders) via the
  canonical :mod:`backend.shared.fingerprint` module — shared with the
  persistence layer — so real log storms actually dedup.
* **Escalation cooldown**: once an incident ESCALATES, the same
  fingerprint is suppressed for ``escalation_cooldown_seconds``
  (default 30 min). Without this, an unfixable recurring error would
  re-trigger the full agent pipeline every dedup-window expiry and
  burn the LLM budget retrying a fix that already failed.
* **Real memory compaction**: when the store crosses the configured
  threshold, near-duplicate entries (same root_cause+fix) are merged
  and the store is trimmed to the threshold — previously this was a
  log line with no action, letting retrieval quality degrade forever.
* **Escalation notifications**: an optional ``notifier`` (see
  :class:`backend.services.notifier.WebhookNotifier`) is pinged on
  terminal states so a human actually finds out when Sentry gives up.
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
from backend.shared import fingerprint as fp
from backend.shared.agent_throttle import AgentThrottle
from backend.shared.ai_gateway import AIGateway
from backend.shared.circuit_breaker import CostCircuitBreaker
from backend.shared.config import AppConfig
from backend.shared.interfaces import (
    IAuditLog,
    ILLMClient,
    IMemoryStore,
    IOrchestrator,
    IToolExecutor,
)
from backend.shared.metrics import (
    inc_circuit_breaker_trip,
    inc_event_deduped,
    inc_event_suppressed,
    inc_incident,
    inc_memory_compaction,
)
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
# After an ESCALATED terminal state, suppress the same fingerprint for
# this long (seconds). 0 disables suppression.
DEFAULT_ESCALATION_COOLDOWN_SECONDS = 1800


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
        audit_log: IAuditLog | None = None,
        vault: IVault | None = None,
        gateway: AIGateway | None = None,
        throttle: AgentThrottle | None = None,
        registry: TrustedToolRegistry | None = None,
        *,
        incident_repo: Any | None = None,  # IncidentRepository; optional keyword
        orchestrator_timeout_seconds: int = DEFAULT_ORCH_TIMEOUT_SECONDS,
        dedup_window_seconds: int = DEFAULT_DEDUP_WINDOW_SECONDS,
        broadcaster: Any | None = None,  # P2.4: IncidentBroadcaster; optional
        escalation_cooldown_seconds: int = DEFAULT_ESCALATION_COOLDOWN_SECONDS,
        notifier: Any | None = None,  # WebhookNotifier; optional
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
        self._escalation_cooldown = escalation_cooldown_seconds
        self._notifier = notifier
        self._active_incidents: dict[str, Incident] = {}
        # Use deque with maxlen so FIFO trimming is O(1) and correct by construction.
        self._resolved_incidents: deque[Incident] = deque(maxlen=MAX_RESOLVED_INCIDENTS)

        # --- P1.3 in-memory dedup cache ---
        # Maps fingerprint -> monotonic-clock timestamp of last accepted event.
        # Serves the `incident_repo is None` path and is trimmed lazily on
        # every `handle_event` to keep memory bounded.
        self._recent_fingerprints: dict[str, float] = {}
        self._dedup_lock = asyncio.Lock()
        # Fingerprints whose last incident ESCALATED, with the monotonic
        # timestamp of the escalation. Consulted BEFORE dedup so a
        # known-unfixable error is suppressed for the full cooldown,
        # not just the dedup window.
        self._escalated_fingerprints: dict[str, float] = {}

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

        Delegates to the canonical
        :func:`backend.shared.fingerprint.compute_fingerprint` — the
        SAME function used by
        ``backend.persistence.repositories.incident_repo.compute_fingerprint``
        — so the in-memory cache and the DB dedup query can never
        disagree about what counts as "the same error". The line is
        normalized first (timestamps, PIDs, request ids, IPs collapse
        to placeholders), which is what makes real log storms dedup.
        """
        return fp.compute_fingerprint(
            event.source_file or "",
            event.matched_pattern or "",
            event.line_content or "",
        )

    def _is_suppressed(self, fingerprint: str) -> bool:
        """Return True if this fingerprint escalated within the cooldown.

        An ESCALATED incident means the agents already tried and failed
        to fix this exact error. Re-running the full pipeline every time
        the dedup window expires would burn the LLM budget retrying a
        known-failed fix — so we suppress for ``escalation_cooldown``
        seconds and let the operator (notified via webhook) intervene.
        """
        if not fingerprint or self._escalation_cooldown <= 0:
            return False
        ts = self._escalated_fingerprints.get(fingerprint)
        if ts is None:
            return False
        if (time.monotonic() - ts) < self._escalation_cooldown:
            return True
        # Cooldown expired — allow a fresh attempt.
        self._escalated_fingerprints.pop(fingerprint, None)
        return False

    def _record_escalation(self, fingerprint: str) -> None:
        """Mark a fingerprint as recently escalated (starts the cooldown)."""
        if not fingerprint or self._escalation_cooldown <= 0:
            return
        now = time.monotonic()
        # Opportunistic eviction so the map stays bounded.
        cutoff = now - (self._escalation_cooldown * 2)
        stale = [k for k, ts in self._escalated_fingerprints.items() if ts < cutoff]
        for k in stale:
            self._escalated_fingerprints.pop(k, None)
        self._escalated_fingerprints[fingerprint] = now

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
                stale = [key for key, ts in self._recent_fingerprints.items() if ts < cutoff]
                for key in stale:
                    self._recent_fingerprints.pop(key, None)

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

        fingerprint = self._compute_event_fingerprint(event)

        # --- Escalation cooldown: known-failed errors are suppressed ---
        if self._is_suppressed(fingerprint):
            logger.info(
                "suppress: skipping event (fingerprint escalated within %ds): %s",
                self._escalation_cooldown, (event.line_content or "")[:80],
            )
            inc_event_suppressed()
            return None

        # --- P1.3: fingerprint dedup ---
        if await self._is_duplicate(fingerprint):
            logger.info(
                "dedup: skipping event (fingerprint seen within %ds): %s",
                self._dedup_window, (event.line_content or "")[:80],
            )
            inc_event_deduped()
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

            # --- Escalation cooldown bookkeeping ---
            if incident.state == IncidentState.ESCALATED:
                self._record_escalation(fingerprint)

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

            # --- Escalation/resolution webhook (fire-and-forget) ---
            if self._notifier is not None:
                try:
                    self._notifier.notify_incident(incident)
                except Exception:  # pragma: no cover — defensive
                    logger.exception("notifier failed for %s", incident_id)

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
            # Keyword extraction (stop-words removed, distinctive tokens
            # kept) — replaces the naive first-5-words split that made
            # every entry match every query on tokens like "error".
            vectors=incident.vectors or fp.extract_keywords(incident.symptom),
            timestamp=datetime.now(UTC).isoformat(),
        )
        await self._memory.save(entry)

        count = await self._memory.get_count()
        if count > self._config.memory.max_incidents_before_compaction:
            logger.info("Memory compaction threshold reached — compacting")
            try:
                await self._compact_memory()
            except Exception:  # pragma: no cover — never fail the resolve path
                logger.exception("memory compaction failed")

    async def _compact_memory(self) -> None:
        """Compact long-term memory once it exceeds the configured threshold.

        Strategy (deterministic, zero LLM spend):

        1. **Merge near-duplicates** — entries with the same normalized
           ``(root_cause, fix)`` collapse into the newest occurrence,
           with their retrieval vectors unioned so the merged entry
           still matches every symptom phrasing that any of its
           ancestors matched.
        2. **Trim to threshold** — if still over the limit, keep the
           most recent ``max_incidents_before_compaction`` entries
           (recency wins: newer fixes reflect the current codebase).

        This was the B1 backlog item: previously the threshold check
        only emitted a log line, so memory grew unboundedly and
        retrieval relevance degraded as noise accumulated.
        """
        entries = await self._memory.load()
        threshold = self._config.memory.max_incidents_before_compaction
        if len(entries) <= threshold:
            return

        merged: dict[tuple[str, str], MemoryEntry] = {}
        for e in entries:  # load() returns oldest → newest
            key = (
                (e.root_cause or "").strip().lower(),
                (e.fix or "").strip().lower(),
            )
            prev = merged.get(key)
            if prev is not None:
                # Newest entry wins; union vectors so retrieval recall
                # is preserved across the merge.
                e.vectors = list(dict.fromkeys([*(prev.vectors or []), *(e.vectors or [])]))
            merged[key] = e
        compacted = list(merged.values())

        if len(compacted) > threshold:
            compacted = compacted[-threshold:]

        await self._memory.compact(compacted)
        inc_memory_compaction()
        logger.info(
            "Memory compacted: %d entries -> %d", len(entries), len(compacted)
        )

    async def get_active_incidents(self) -> list[Incident]:
        return list(self._active_incidents.values())

    async def get_status(self) -> dict[str, Any]:
        return {
            "active_incidents": len(self._active_incidents),
            "resolved_total": len(self._resolved_incidents),
            "circuit_breaker": self._cb.get_status(),
            "mode": self._config.security.mode.value,
        }
