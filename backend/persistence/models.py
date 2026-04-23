"""
P1.2 — SQLAlchemy 2.0 ORM models.

Portable between Postgres (production) and SQLite (dev/CI). The JSON
columns use SQLAlchemy's generic ``JSON`` type, which picks ``jsonb`` on
Postgres and ``TEXT`` with application-side serialization on SQLite.

Tables
------
* ``incidents`` — every state transition of every incident.
* ``memory_entries`` — post-resolution memory rows (replaces JSONMemoryStore).
* ``memory_state`` — singleton key/value table for the system fingerprint.
* ``audit_log`` — hash-chained, append-only audit rows.
* ``api_tokens`` — bearer-token auth state (populated in P2.1).

Immutability of ``audit_log`` is enforced two ways:

1. The ``PostgresAuditLog`` repo never issues UPDATE or DELETE.
2. A Postgres trigger (see ``migrations/env.py``) raises on any
   UPDATE/DELETE. On SQLite, trigger-level enforcement is skipped —
   only the application-level guard applies. This is acceptable for
   local dev because SQLite is only used in the in-process CI path.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DDL, JSON, DateTime, Index, Integer, String, Text, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utc_now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Declarative base for all Sentry persistence models."""


# ────────────────────────────────────────────────────────────────────
# Incidents
# ────────────────────────────────────────────────────────────────────


class IncidentRow(Base):
    """Persistent projection of :class:`backend.shared.models.Incident`."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)

    symptom: Mapped[str] = mapped_column(Text, nullable=False)
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    fix_applied: Mapped[str | None] = mapped_column(Text, nullable=True)
    triage_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    commit_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cost_usd: Mapped[float] = mapped_column(nullable=False, default=0.0)

    # Normalized (source_file|matched_pattern|line) fingerprint for dedup.
    fingerprint_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    # JSON blobs — activity log entries, the raw log events, the vectors.
    activity_log: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    log_events: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    vectors: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, index=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )


Index("ix_incidents_state_created", IncidentRow.state, IncidentRow.created_at.desc())


# ────────────────────────────────────────────────────────────────────
# Memory
# ────────────────────────────────────────────────────────────────────


class MemoryEntryRow(Base):
    """Persistent projection of :class:`backend.shared.models.MemoryEntry`."""

    __tablename__ = "memory_entries"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    symptom: Mapped[str] = mapped_column(Text, nullable=False)
    root_cause: Mapped[str] = mapped_column(Text, nullable=False)
    fix: Mapped[str] = mapped_column(Text, nullable=False)
    vectors: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    timestamp: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, index=True
    )


class MemoryStateRow(Base):
    """Singleton key/value table for the system fingerprint and other meta."""

    __tablename__ = "memory_state"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )


# ────────────────────────────────────────────────────────────────────
# Audit log
# ────────────────────────────────────────────────────────────────────


class AuditLogRow(Base):
    """Immutable, hash-chained audit entry.

    ``timestamp_iso`` stores the exact ISO-8601 timestamp string that
    participated in the hash. We keep a parallel DateTime ``timestamp``
    column for indexing + human-friendly SQL queries, but the hash is
    computed over the string form so verification is lossless even when
    the DB round-trips timezone metadata.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, index=True
    )
    timestamp_iso: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    result: Mapped[str] = mapped_column(Text, nullable=False, default="")
    chain_of_thought: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Extra JSON metadata, free-form.
    extra_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


# ────────────────────────────────────────────────────────────────────
# API tokens (populated in P2.1)
# ────────────────────────────────────────────────────────────────────


class ApiTokenRow(Base):
    """Bearer-token auth row. Populated by P2.1."""

    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # SHA-256 hash of the raw token — the token itself never persisted.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ────────────────────────────────────────────────────────────────────
# SEC-30 — audit_log append-only triggers (defense-in-depth).
#
# These DDL event listeners fire right after the ``audit_log`` table is
# created so that ``metadata.create_all()`` and Alembic share the same
# trigger surface. The application layer already refuses to issue
# UPDATE / DELETE against ``audit_log`` (see
# ``backend/persistence/repositories/audit_repo.py``); the DB-level
# triggers are a second line of defense against a rogue operator with
# direct DB access.
#
# We generate dialect-specific DDL via the ``DDL.execute_if`` guard:
# Postgres gets a PL/pgSQL function + BEFORE UPDATE OR DELETE trigger;
# SQLite gets two BEFORE UPDATE / BEFORE DELETE triggers that use
# ``RAISE(ABORT, ...)``. Other dialects (e.g. MSSQL, MySQL) silently
# skip — they currently aren't supported by Sentry.
# ────────────────────────────────────────────────────────────────────

_PG_AUDIT_TRIGGER_FN = DDL(
    """
    CREATE OR REPLACE FUNCTION sentry_audit_log_immutable()
    RETURNS TRIGGER AS $$
    BEGIN
        RAISE EXCEPTION 'audit_log is append-only: % rejected', TG_OP
            USING ERRCODE = '42000';
    END;
    $$ LANGUAGE plpgsql;
    """
)

_PG_AUDIT_TRIGGER = DDL(
    """
    DROP TRIGGER IF EXISTS sentry_audit_log_no_update ON audit_log;
    CREATE TRIGGER sentry_audit_log_no_update
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION sentry_audit_log_immutable();
    """
)

_SQLITE_AUDIT_NO_UPDATE = DDL(
    """
    CREATE TRIGGER IF NOT EXISTS sentry_audit_log_no_update
    BEFORE UPDATE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE rejected');
    END;
    """
)

_SQLITE_AUDIT_NO_DELETE = DDL(
    """
    CREATE TRIGGER IF NOT EXISTS sentry_audit_log_no_delete
    BEFORE DELETE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only: DELETE rejected');
    END;
    """
)


event.listen(
    AuditLogRow.__table__,
    "after_create",
    _PG_AUDIT_TRIGGER_FN.execute_if(dialect="postgresql"),
)
event.listen(
    AuditLogRow.__table__,
    "after_create",
    _PG_AUDIT_TRIGGER.execute_if(dialect="postgresql"),
)
event.listen(
    AuditLogRow.__table__,
    "after_create",
    _SQLITE_AUDIT_NO_UPDATE.execute_if(dialect="sqlite"),
)
event.listen(
    AuditLogRow.__table__,
    "after_create",
    _SQLITE_AUDIT_NO_DELETE.execute_if(dialect="sqlite"),
)


__all__ = [
    "ApiTokenRow",
    "AuditLogRow",
    "Base",
    "IncidentRow",
    "MemoryEntryRow",
    "MemoryStateRow",
]


