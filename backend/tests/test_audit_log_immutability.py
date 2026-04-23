"""
SEC-30 — DB-level audit_log immutability tests.

The application layer (``PostgresAuditLog``) already refuses to issue
UPDATE / DELETE against ``audit_log``. These tests exercise the
**database-level** defense — the DDL triggers created by
``backend.persistence.models`` and the Alembic migration — so that a
rogue operator with direct SQL access cannot rewrite forensic history
without the trigger screaming.

The trigger is dialect-aware:

* **Postgres**: ``CREATE TRIGGER ... BEFORE UPDATE OR DELETE`` bound to
  a PL/pgSQL function that ``RAISE EXCEPTION``-s. Tested end-to-end in
  CI against the real Postgres service.
* **SQLite**: two ``CREATE TRIGGER ... RAISE(ABORT, ...)`` statements
  (one for UPDATE, one for DELETE). Tested in-process here so every
  developer run exercises the defense.

The tests use the same ``build_database`` + ``create_all`` bootstrap as
the rest of the persistence suite — no Alembic required, because the
DDL event listeners in ``backend/persistence/models.py`` attach the
triggers right after the ``audit_log`` table is created.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import text

from backend.persistence.models import AuditLogRow
from backend.persistence.repositories.audit_repo import PostgresAuditLog
from backend.persistence.session import build_database


@pytest.fixture
async def audit_db(tmp_path: Path):
    """One fresh file-backed SQLite DB per test with audit_log + triggers."""
    db_path = tmp_path / "audit_immutable.db"
    database = build_database(f"sqlite+aiosqlite:///{db_path}")
    await database.create_all()
    try:
        yield database
    finally:
        await database.dispose()


async def _insert_one(database) -> int:
    """Insert a legitimate audit row via the repo, return its row id."""
    repo = PostgresAuditLog(database)
    repo.log_action(
        agent_id="sec30-agent",
        action="initial-write",
        detail="seed",
        result="ok",
    )
    # log_action hops a worker thread — give the background insert a
    # moment to commit. The `_flush` helper is internal, so we just poll
    # until a row shows up.
    async with database.sessionmaker() as session:
        for _ in range(50):
            result = await session.execute(
                text("SELECT id FROM audit_log ORDER BY id DESC LIMIT 1")
            )
            row = result.first()
            if row is not None:
                return int(row[0])
            import asyncio

            await asyncio.sleep(0.05)
    raise AssertionError("audit row never landed after 2.5 s")


class TestAuditLogImmutability:
    """SEC-30 — the DB-level triggers must reject UPDATE and DELETE."""

    @pytest.mark.asyncio
    async def test_trigger_exists_on_sqlite(self, audit_db):
        """Both ``sentry_audit_log_no_update`` + ``_no_delete`` must be
        installed after ``create_all()``."""
        async with audit_db.sessionmaker() as session:
            result = await session.execute(
                text(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='trigger' AND tbl_name='audit_log' "
                    "ORDER BY name"
                )
            )
            names = [row[0] for row in result.fetchall()]
        assert "sentry_audit_log_no_delete" in names
        assert "sentry_audit_log_no_update" in names

    @pytest.mark.asyncio
    async def test_update_is_rejected(self, audit_db):
        """Raw UPDATE against a seeded row must be blocked by the trigger."""
        row_id = await _insert_one(audit_db)
        async with audit_db.sessionmaker() as session:
            with pytest.raises(Exception) as exc_info:
                await session.execute(
                    text("UPDATE audit_log SET detail = 'tampered' WHERE id = :i"),
                    {"i": row_id},
                )
                await session.commit()
        # The exception message must mention append-only / rejected so an
        # operator hitting this knows exactly what's going on.
        msg = str(exc_info.value).lower()
        assert "append-only" in msg or "rejected" in msg

    @pytest.mark.asyncio
    async def test_delete_is_rejected(self, audit_db):
        """Raw DELETE must be blocked by the trigger."""
        row_id = await _insert_one(audit_db)
        async with audit_db.sessionmaker() as session:
            with pytest.raises(Exception) as exc_info:
                await session.execute(
                    text("DELETE FROM audit_log WHERE id = :i"),
                    {"i": row_id},
                )
                await session.commit()
        msg = str(exc_info.value).lower()
        assert "append-only" in msg or "rejected" in msg

    @pytest.mark.asyncio
    async def test_insert_still_works(self, audit_db):
        """Positive control: INSERT is the ONLY allowed mutation and must
        continue to function normally."""
        async with audit_db.sessionmaker() as session:
            await session.execute(
                text(
                    "INSERT INTO audit_log ("
                    "timestamp, timestamp_iso, agent_id, action, detail, "
                    "result, chain_of_thought, extra_metadata, prev_hash, "
                    "entry_hash) VALUES ("
                    ":ts, :ts_iso, :aid, :act, :det, :res, :cot, '{}', "
                    ":ph, :eh"
                    ")"
                ),
                {
                    "ts": datetime.now(UTC),
                    "ts_iso": datetime.now(UTC).isoformat(),
                    "aid": "positive-control",
                    "act": "insert",
                    "det": "",
                    "res": "",
                    "cot": "",
                    "ph": "0" * 64,
                    "eh": "1" * 64,
                },
            )
            await session.commit()

        # And we can read it back.
        async with audit_db.sessionmaker() as session:
            result = await session.execute(
                text("SELECT COUNT(*) FROM audit_log WHERE agent_id = :aid"),
                {"aid": "positive-control"},
            )
            count = result.scalar()
        assert count == 1

    @pytest.mark.asyncio
    async def test_rows_survive_tamper_attempt(self, audit_db):
        """After the trigger fires, the original row must be UNCHANGED."""
        row_id = await _insert_one(audit_db)

        async with audit_db.sessionmaker() as session:
            result = await session.execute(
                text("SELECT detail FROM audit_log WHERE id = :i"),
                {"i": row_id},
            )
            original_detail = result.scalar()

        # Attempt tamper.
        async with audit_db.sessionmaker() as session:
            with pytest.raises(Exception):
                await session.execute(
                    text("UPDATE audit_log SET detail = 'tampered' WHERE id = :i"),
                    {"i": row_id},
                )
                await session.commit()

        # Verify row unchanged.
        async with audit_db.sessionmaker() as session:
            result = await session.execute(
                text("SELECT detail FROM audit_log WHERE id = :i"),
                {"i": row_id},
            )
            current_detail = result.scalar()
        assert current_detail == original_detail
        assert current_detail != "tampered"


class TestAuditLogAlembicMigrationTriggers:
    """SEC-30 — ensure the Alembic initial-schema migration also installs
    the triggers (parity with ``create_all`` path).

    The initial migration file has a ``dialect.name == "sqlite"`` branch
    that issues the same triggers. We verify here that the trigger names
    defined in the migration match what we listen for at table-create
    time.
    """

    def test_migration_trigger_names_match_create_all(self):
        """If an operator runs ``alembic upgrade head`` against SQLite,
        they must end up with triggers named exactly the same as the
        ``create_all`` path; otherwise the E2E SEC-30 test would fail
        on some deployments but not others."""
        from pathlib import Path

        migration_path = (
            Path(__file__).resolve().parents[1]
            / "persistence"
            / "migrations"
            / "versions"
            / "20260422_0001_initial_schema.py"
        )
        src = migration_path.read_text(encoding="utf-8")

        # SQLite branch
        assert "sentry_audit_log_no_update" in src
        assert "sentry_audit_log_no_delete" in src
        assert "RAISE(ABORT" in src

        # Postgres branch
        assert "sentry_audit_log_immutable" in src
        assert "BEFORE UPDATE OR DELETE ON audit_log" in src



# ─────────────────────────────────────────────────────────────────────
# Postgres-only tests — run when ``SENTRY_TEST_PG_URL`` is set. Local
# developer runs skip this; CI with a Postgres service executes it.
# ─────────────────────────────────────────────────────────────────────


@pytest.fixture
async def pg_audit_db():
    """Real-Postgres audit_log database, gated by env var. Skipped when
    ``SENTRY_TEST_PG_URL`` is not set."""
    import os

    url = os.getenv("SENTRY_TEST_PG_URL")
    if not url:
        pytest.skip("SENTRY_TEST_PG_URL not set; skipping real-Postgres SEC-30 test")

    database = build_database(url)
    # Fresh schema per run — drop and recreate the single table (the
    # rest of the schema doesn't matter here).
    async with database.engine.begin() as conn:
        # Drop dependent trigger + function so drop_all doesn't hit them.
        await conn.exec_driver_sql(
            "DROP TRIGGER IF EXISTS sentry_audit_log_no_update ON audit_log;"
        )
        await conn.exec_driver_sql(
            "DROP FUNCTION IF EXISTS sentry_audit_log_immutable();"
        )
        await conn.exec_driver_sql("DROP TABLE IF EXISTS audit_log CASCADE;")
    async with database.engine.begin() as conn:
        await conn.run_sync(AuditLogRow.__table__.create)
    try:
        yield database
    finally:
        await database.dispose()


class TestAuditLogImmutabilityPostgres:
    """SEC-30 — Postgres path (gated by env var)."""

    @pytest.mark.asyncio
    async def test_postgres_update_rejected(self, pg_audit_db):
        row_id = await _insert_one(pg_audit_db)
        async with pg_audit_db.sessionmaker() as session:
            with pytest.raises(Exception) as exc_info:
                await session.execute(
                    text("UPDATE audit_log SET detail = 'tampered' WHERE id = :i"),
                    {"i": row_id},
                )
                await session.commit()
        assert "append-only" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_postgres_delete_rejected(self, pg_audit_db):
        row_id = await _insert_one(pg_audit_db)
        async with pg_audit_db.sessionmaker() as session:
            with pytest.raises(Exception) as exc_info:
                await session.execute(
                    text("DELETE FROM audit_log WHERE id = :i"),
                    {"i": row_id},
                )
                await session.commit()
        assert "append-only" in str(exc_info.value).lower()
