"""
P1.2 — Unit tests for the persistence layer.

Drives the SQLAlchemy-backed repositories against an in-memory SQLite
database so the suite runs with no Docker / Postgres dependency. The
same code paths run against real Postgres in CI / integration.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend.persistence.repositories.audit_repo import PostgresAuditLog
from backend.persistence.repositories.incident_repo import (
    IncidentRepository,
    compute_fingerprint,
)
from backend.persistence.repositories.memory_repo import PostgresMemoryRepo
from backend.persistence.session import build_database
from backend.shared.models import (
    ActivityType,
    Incident,
    IncidentSeverity,
    IncidentState,
    LogEvent,
    MemoryEntry,
)


# ──────────────────────────────────────────────────────────────────────
# Fixture: one fresh file-backed SQLite database per test.
#
# We deliberately use a file (not :memory:) because the PostgresAuditLog
# spins a worker thread for its sync ``log_action`` which would get its
# own in-memory DB otherwise.
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
async def db(tmp_path: Path):
    db_path = tmp_path / "sentry_test.db"
    database = build_database(f"sqlite+aiosqlite:///{db_path}")
    await database.create_all()
    try:
        yield database
    finally:
        await database.dispose()


# ══════════════════════════════════════════════════════════════════════
# PostgresMemoryRepo
# ══════════════════════════════════════════════════════════════════════


class TestPostgresMemoryRepo:
    @pytest.mark.asyncio
    async def test_round_trip_save_and_load(self, db):
        repo = PostgresMemoryRepo(db)
        entry = MemoryEntry(
            id="MEM-1",
            symptom="connection refused",
            root_cause="db port closed",
            fix="open port 5432",
            vectors=["connection", "db"],
        )
        await repo.save(entry)
        loaded = await repo.load()
        assert len(loaded) == 1
        assert loaded[0].id == "MEM-1"
        assert loaded[0].symptom == "connection refused"
        assert loaded[0].vectors == ["connection", "db"]

    @pytest.mark.asyncio
    async def test_save_is_idempotent_by_id(self, db):
        repo = PostgresMemoryRepo(db)
        await repo.save(
            MemoryEntry(id="M", symptom="x", root_cause="y", fix="z", vectors=[])
        )
        # Overwrite same id with new fix
        await repo.save(
            MemoryEntry(id="M", symptom="x", root_cause="y", fix="NEW", vectors=[])
        )
        loaded = await repo.load()
        assert len(loaded) == 1
        assert loaded[0].fix == "NEW"

    @pytest.mark.asyncio
    async def test_get_relevant_ranks_by_overlap(self, db):
        repo = PostgresMemoryRepo(db)
        await repo.save(
            MemoryEntry(
                id="A", symptom="s", root_cause="r", fix="f",
                vectors=["db", "timeout"],
            )
        )
        await repo.save(
            MemoryEntry(
                id="B", symptom="s", root_cause="r", fix="f",
                vectors=["db", "timeout", "refused"],
            )
        )
        await repo.save(
            MemoryEntry(
                id="C", symptom="s", root_cause="r", fix="f",
                vectors=["unrelated"],
            )
        )
        hits = await repo.get_relevant(["db", "timeout", "refused"])
        assert [e.id for e in hits] == ["B", "A"]  # B wins with 3, A with 2
        # C has zero overlap — not returned
        assert "C" not in {e.id for e in hits}

    @pytest.mark.asyncio
    async def test_fingerprint_round_trip(self, db):
        repo = PostgresMemoryRepo(db)
        assert await repo.get_fingerprint() == ""  # empty on cold start
        await repo.set_fingerprint("abc123")
        assert await repo.get_fingerprint() == "abc123"
        await repo.set_fingerprint("def456")
        assert await repo.get_fingerprint() == "def456"

    @pytest.mark.asyncio
    async def test_compact_replaces_everything(self, db):
        repo = PostgresMemoryRepo(db)
        for i in range(5):
            await repo.save(
                MemoryEntry(
                    id=f"M{i}", symptom="s", root_cause="r",
                    fix=f"f{i}", vectors=[],
                )
            )
        summary = [MemoryEntry(id="SUMMARY", symptom="s", root_cause="r", fix="f", vectors=[])]
        await repo.compact(summary)
        all_ = await repo.load()
        assert [e.id for e in all_] == ["SUMMARY"]

    @pytest.mark.asyncio
    async def test_get_count(self, db):
        repo = PostgresMemoryRepo(db)
        assert await repo.get_count() == 0
        for i in range(3):
            await repo.save(
                MemoryEntry(
                    id=f"M{i}", symptom="s", root_cause="r",
                    fix="f", vectors=[],
                )
            )
        assert await repo.get_count() == 3


# ══════════════════════════════════════════════════════════════════════
# PostgresAuditLog
# ══════════════════════════════════════════════════════════════════════


class TestPostgresAuditLog:
    @pytest.mark.asyncio
    async def test_log_action_appends_hash_chain(self, db):
        log = PostgresAuditLog(db)
        h1 = log.log_action("agent-1", "triage", "incident INC-1", "ok")
        h2 = log.log_action("agent-1", "diagnose", "incident INC-1", "ok")

        assert h1 != h2
        assert len(h1) == 64  # sha256 hex
        assert log.verify_integrity() is True

    @pytest.mark.asyncio
    async def test_verify_integrity_detects_tamper(self, db):
        log = PostgresAuditLog(db)
        log.log_action("agent-1", "a", "d1", "r1")
        log.log_action("agent-1", "b", "d2", "r2")
        assert log.verify_integrity() is True

        # Tamper: UPDATE the detail of the first row directly in the DB.
        # (In real Postgres a trigger would block this; SQLite has no such
        # trigger — which is why we enforce via the sync repo API too.)
        from sqlalchemy import update
        from backend.persistence.models import AuditLogRow
        async with db.sessionmaker() as session:
            await session.execute(
                update(AuditLogRow)
                .where(AuditLogRow.id == 1)
                .values(detail="TAMPERED")
            )
            await session.commit()

        assert log.verify_integrity() is False

    @pytest.mark.asyncio
    async def test_read_all_returns_ordered_entries(self, db):
        log = PostgresAuditLog(db)
        for i in range(3):
            log.log_action("agent-1", f"action-{i}", "d", "r")
        entries = log.read_all()
        assert len(entries) == 3
        assert [e["action"] for e in entries] == ["action-0", "action-1", "action-2"]
        # Hash chain: entry N's prev_hash must equal entry N-1's entry_hash.
        assert entries[0]["prev_hash"] == "genesis"
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
        assert entries[2]["prev_hash"] == entries[1]["entry_hash"]

    @pytest.mark.asyncio
    async def test_entry_count(self, db):
        log = PostgresAuditLog(db)
        assert log.get_entry_count() == 0
        log.log_action("agent-1", "a", "d", "r")
        log.log_action("agent-1", "b", "d", "r")
        assert log.get_entry_count() == 2


# ══════════════════════════════════════════════════════════════════════
# IncidentRepository — persistence + dedup
# ══════════════════════════════════════════════════════════════════════


class TestIncidentRepository:
    @pytest.mark.asyncio
    async def test_save_and_get(self, db):
        repo = IncidentRepository(db)
        inc = Incident(
            id="INC-1", symptom="connection refused",
            state=IncidentState.TRIAGE,
            severity=IncidentSeverity.HIGH,
        )
        inc.log_activity(ActivityType.LLM_CALL, "triage", "Triage LLM call", "...")
        await repo.save(inc)

        fetched = await repo.get("INC-1")
        assert fetched is not None
        assert fetched.id == "INC-1"
        assert fetched.symptom == "connection refused"
        assert fetched.state == IncidentState.TRIAGE
        assert fetched.severity == IncidentSeverity.HIGH
        assert len(fetched.activity_log) == 1
        assert fetched.activity_log[0].activity_type == ActivityType.LLM_CALL

    @pytest.mark.asyncio
    async def test_save_is_upsert(self, db):
        repo = IncidentRepository(db)
        inc = Incident(id="INC-1", symptom="s", state=IncidentState.TRIAGE)
        await repo.save(inc)

        inc.state = IncidentState.DIAGNOSIS
        inc.root_cause = "it broke"
        await repo.save(inc)

        fetched = await repo.get("INC-1")
        assert fetched.state == IncidentState.DIAGNOSIS
        assert fetched.root_cause == "it broke"

    @pytest.mark.asyncio
    async def test_transition_updates_state_and_resolved_at(self, db):
        repo = IncidentRepository(db)
        await repo.save(Incident(id="INC-1", symptom="s", state=IncidentState.TRIAGE))
        await repo.transition("INC-1", IncidentState.RESOLVED)

        fetched = await repo.get("INC-1")
        assert fetched.state == IncidentState.RESOLVED
        assert fetched.resolved_at is not None

    @pytest.mark.asyncio
    async def test_list_active_excludes_terminal_states(self, db):
        repo = IncidentRepository(db)
        await repo.save(Incident(id="A", symptom="x", state=IncidentState.TRIAGE))
        await repo.save(Incident(id="B", symptom="x", state=IncidentState.DIAGNOSIS))
        await repo.save(Incident(id="C", symptom="x", state=IncidentState.RESOLVED))
        await repo.save(Incident(id="D", symptom="x", state=IncidentState.ESCALATED))

        active = await repo.list_active()
        assert {i.id for i in active} == {"A", "B"}

    @pytest.mark.asyncio
    async def test_list_resolved_respects_limit(self, db):
        repo = IncidentRepository(db)
        for i in range(5):
            inc = Incident(
                id=f"R{i}", symptom="x", state=IncidentState.RESOLVED,
                resolved_at=datetime.now(timezone.utc),
            )
            await repo.save(inc)
        resolved = await repo.list_resolved(limit=3)
        assert len(resolved) == 3

    @pytest.mark.asyncio
    async def test_dedupe_fingerprint_within_window(self, db):
        repo = IncidentRepository(db)
        fp = hashlib.sha256(b"source|pat|line").hexdigest()
        inc = Incident(id="INC-1", symptom="x", state=IncidentState.TRIAGE)
        await repo.save(inc, fingerprint=fp)

        # Same fingerprint, 0 s later → dedup hit.
        assert await repo.dedupe_fingerprint(fp, window_seconds=60) is True

        # Unknown fingerprint → no dedup.
        other = hashlib.sha256(b"different").hexdigest()
        assert await repo.dedupe_fingerprint(other, window_seconds=60) is False

    @pytest.mark.asyncio
    async def test_dedupe_fingerprint_outside_window(self, db):
        repo = IncidentRepository(db)
        fp = hashlib.sha256(b"source|pat|line").hexdigest()
        inc = Incident(id="INC-1", symptom="x", state=IncidentState.TRIAGE)
        await repo.save(inc, fingerprint=fp)

        # Window = 0 s — even the just-inserted row is outside.
        assert await repo.dedupe_fingerprint(fp, window_seconds=0) is False

    def test_compute_fingerprint_is_deterministic_and_line_sensitive(self):
        e1 = LogEvent(source_file="a.log", line_content="ERROR X", matched_pattern="error")
        e2 = LogEvent(source_file="a.log", line_content="ERROR X", matched_pattern="error")
        e3 = LogEvent(source_file="a.log", line_content="ERROR Y", matched_pattern="error")
        assert compute_fingerprint(e1) == compute_fingerprint(e2)
        assert compute_fingerprint(e1) != compute_fingerprint(e3)


# ══════════════════════════════════════════════════════════════════════
# End-to-end smoke through build_container with DATABASE_URL
# ══════════════════════════════════════════════════════════════════════


class TestFactoryWithDatabaseUrl:
    def test_build_container_wires_postgres_repos_when_url_set(self, tmp_path):
        """Setting DATABASE_URL must replace the JSON memory store + file audit log."""
        from backend.shared.factory import build_container
        from backend.shared.settings import Settings

        db_file = tmp_path / "sentry.db"
        settings = Settings(
            database_url=f"sqlite+aiosqlite:///{db_file}",
            audit_log_path=str(tmp_path / "unused_audit.jsonl"),
            memory_file_path=str(tmp_path / "unused_memory.json"),
            stop_file_path=str(tmp_path / "STOP"),
            project_root=str(tmp_path),
            patchable_root=str(tmp_path / "patchable"),
        )

        # Avoid the LLM client trying to reach the real Anthropic API by
        # passing a fake.
        class _FakeLLM:
            async def analyze(self, *a, **kw): return {"content": ""}
            async def get_usage(self): return {}

        container = build_container(settings, llm_override=_FakeLLM())
        try:
            assert container.database is not None
            assert container.incident_repo is not None
            # memory and audit_log must be the Postgres-backed classes.
            from backend.persistence.repositories.audit_repo import PostgresAuditLog
            from backend.persistence.repositories.memory_repo import PostgresMemoryRepo
            assert isinstance(container.memory, PostgresMemoryRepo)
            assert isinstance(container.audit_log, PostgresAuditLog)
        finally:
            import asyncio
            asyncio.get_event_loop().run_until_complete(container.shutdown())

    def test_build_container_defaults_to_sqlite_when_no_url(self, tmp_path):
        """Empty DATABASE_URL (P3.4b): synthesizes a local sqlite database for
        memory + incidents and keeps the JSONL file audit log.
        """
        from backend.persistence.repositories.memory_repo import PostgresMemoryRepo
        from backend.shared.audit_log import ImmutableAuditLog
        from backend.shared.factory import build_container
        from backend.shared.settings import Settings

        settings = Settings(
            database_url=None,
            audit_log_path=str(tmp_path / "audit.jsonl"),
            memory_file_path=str(tmp_path / "memory.json"),
            stop_file_path=str(tmp_path / "STOP"),
            project_root=str(tmp_path),
            patchable_root=str(tmp_path / "patchable"),
        )

        class _FakeLLM:
            async def analyze(self, *a, **kw): return {"content": ""}
            async def get_usage(self): return {}

        container = build_container(settings, llm_override=_FakeLLM())
        try:
            # P3.4b: database is *always* built; sqlite is synthesized
            # next to the memory file.
            assert container.database is not None
            assert container.database.url.startswith("sqlite+aiosqlite:///")
            assert container.incident_repo is not None
            assert isinstance(container.memory, PostgresMemoryRepo)
            # Audit log stays JSONL when no explicit DB URL is set.
            assert isinstance(container.audit_log, ImmutableAuditLog)
        finally:
            import asyncio
            asyncio.get_event_loop().run_until_complete(container.shutdown())
