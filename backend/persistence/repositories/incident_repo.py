"""
P1.2 — ``IncidentRepository``.

Persists every state transition of an :class:`backend.shared.models.Incident`
to the ``incidents`` table so the orchestrator can survive a restart
without losing the in-flight set (this is the real fix for the old
``_active_incidents`` memory-only state).

Also provides ``dedupe_fingerprint(fp, window_seconds)`` which powers
the log-storm dedup step in P1.3.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import and_, select

from backend.persistence.models import IncidentRow
from backend.persistence.session import Database
from backend.shared.models import (
    ActivityEntry,
    ActivityType,
    Incident,
    IncidentSeverity,
    IncidentState,
    LogEvent,
)

logger = logging.getLogger(__name__)


# Terminal states — we still store them, but exclude them from
# ``list_active`` queries so the /api/incidents endpoint can show
# "resolved" and "active" as distinct buckets.
_TERMINAL_STATES = {IncidentState.RESOLVED.value, IncidentState.ESCALATED.value}


def compute_fingerprint(event: LogEvent) -> str:
    """Deterministic dedup key for a log event.

    Format: ``sha256(source_file|matched_pattern|normalized_line)``.
    Timestamps and line numbers are intentionally *not* included so a
    1000-line log storm of the same error collapses to one fingerprint.
    """
    src = event.source_file or ""
    pat = event.matched_pattern or ""
    line = (event.line_content or "").strip()
    material = f"{src}|{pat}|{line}".encode("utf-8", errors="replace")
    return hashlib.sha256(material).hexdigest()


class IncidentRepository:
    """Async repo for persisting incidents and terminal-state queries."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    async def save(self, incident: Incident, fingerprint: Optional[str] = None) -> None:
        """Upsert an incident + its activity log + vectors."""
        async with self._db.sessionmaker() as session:
            row = await session.get(IncidentRow, incident.id)
            if row is None:
                row = IncidentRow(
                    id=incident.id,
                    state=incident.state.value,
                    severity=incident.severity.value,
                    symptom=incident.symptom,
                    root_cause=incident.root_cause,
                    fix_applied=incident.fix_applied,
                    triage_result=incident.triage_result,
                    commit_id=incident.commit_id,
                    retry_count=incident.retry_count,
                    cost_usd=incident.cost_usd,
                    fingerprint_hash=fingerprint,
                    activity_log=[a.to_dict() for a in incident.activity_log],
                    log_events=[_serialize_event(e) for e in incident.log_events],
                    vectors=list(incident.vectors or []),
                    created_at=incident.created_at,
                    resolved_at=incident.resolved_at,
                )
                session.add(row)
            else:
                row.state = incident.state.value
                row.severity = incident.severity.value
                row.symptom = incident.symptom
                row.root_cause = incident.root_cause
                row.fix_applied = incident.fix_applied
                row.triage_result = incident.triage_result
                row.commit_id = incident.commit_id
                row.retry_count = incident.retry_count
                row.cost_usd = incident.cost_usd
                if fingerprint is not None:
                    row.fingerprint_hash = fingerprint
                row.activity_log = [a.to_dict() for a in incident.activity_log]
                row.log_events = [_serialize_event(e) for e in incident.log_events]
                row.vectors = list(incident.vectors or [])
                row.resolved_at = incident.resolved_at
            await session.commit()

    async def transition(self, incident_id: str, new_state: IncidentState) -> None:
        """Cheap state-only update used when the orchestrator only moves the needle."""
        async with self._db.sessionmaker() as session:
            row = await session.get(IncidentRow, incident_id)
            if row is None:
                logger.warning("transition: unknown incident %s", incident_id)
                return
            row.state = new_state.value
            if new_state in (IncidentState.RESOLVED, IncidentState.ESCALATED):
                row.resolved_at = datetime.now(timezone.utc)
            await session.commit()

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def get(self, incident_id: str) -> Optional[Incident]:
        async with self._db.sessionmaker() as session:
            row = await session.get(IncidentRow, incident_id)
        return _row_to_incident(row) if row else None

    async def list_active(self) -> list[Incident]:
        async with self._db.sessionmaker() as session:
            rows = (
                await session.execute(
                    select(IncidentRow)
                    .where(IncidentRow.state.notin_(list(_TERMINAL_STATES)))
                    .order_by(IncidentRow.created_at.asc())
                )
            ).scalars().all()
        return [_row_to_incident(r) for r in rows]

    async def list_resolved(self, limit: int = 20) -> list[Incident]:
        async with self._db.sessionmaker() as session:
            rows = (
                await session.execute(
                    select(IncidentRow)
                    .where(IncidentRow.state == IncidentState.RESOLVED.value)
                    .order_by(IncidentRow.resolved_at.desc().nullslast(), IncidentRow.created_at.desc())
                    .limit(limit)
                )
            ).scalars().all()
        return [_row_to_incident(r) for r in rows]

    # ------------------------------------------------------------------
    # Dedup (P1.3)
    # ------------------------------------------------------------------

    async def dedupe_fingerprint(
        self, fingerprint: str, *, window_seconds: int = 60
    ) -> bool:
        """Return True if an incident with this fingerprint was created within ``window_seconds``.

        Caller is responsible for acting on that signal (early-return from
        ``handle_event``). We deliberately look at ``created_at`` so a
        long-running investigation doesn't keep re-matching.
        """
        if not fingerprint:
            return False
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        async with self._db.sessionmaker() as session:
            result = await session.execute(
                select(IncidentRow.id)
                .where(
                    and_(
                        IncidentRow.fingerprint_hash == fingerprint,
                        IncidentRow.created_at >= cutoff,
                    )
                )
                .limit(1)
            )
            return result.scalar_one_or_none() is not None


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _serialize_event(evt) -> dict:
    if isinstance(evt, dict):
        return evt
    if hasattr(evt, "to_dict"):
        return evt.to_dict()
    return {"line_content": str(evt)}


def _row_to_incident(row: IncidentRow) -> Incident:
    incident = Incident(
        id=row.id,
        symptom=row.symptom,
        state=IncidentState(row.state),
        severity=IncidentSeverity(row.severity),
        root_cause=row.root_cause,
        fix_applied=row.fix_applied,
        triage_result=row.triage_result,
        commit_id=row.commit_id,
        retry_count=row.retry_count,
        cost_usd=row.cost_usd,
        vectors=list(row.vectors or []),
        created_at=row.created_at,
        resolved_at=row.resolved_at,
    )
    # Hydrate activity log
    for item in row.activity_log or []:
        try:
            incident.activity_log.append(
                ActivityEntry(
                    timestamp=datetime.fromisoformat(item["timestamp"]),
                    activity_type=ActivityType(item["activity_type"]),
                    phase=item.get("phase", ""),
                    title=item.get("title", ""),
                    detail=item.get("detail", ""),
                    metadata=item.get("metadata") or {},
                )
            )
        except Exception:  # pragma: no cover
            logger.warning("dropping malformed activity entry for %s", row.id)
    # Log events stay as dicts — same contract as Incident.log_events allows.
    incident.log_events = list(row.log_events or [])
    return incident


__all__ = ["IncidentRepository", "compute_fingerprint"]
