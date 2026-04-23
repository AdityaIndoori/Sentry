"""
Memory store contract tests.

P3.4b note
----------
The legacy ``JSONMemoryStore`` was deleted in P3.4b. Memory is now always
backed by :class:`backend.persistence.repositories.memory_repo.PostgresMemoryRepo`
against an async SQLAlchemy engine (Postgres in prod, SQLite in dev /
tests). This module keeps the original behavioural-coverage tests but
exercises them against ``PostgresMemoryRepo`` with an in-memory SQLite
database so nothing here requires Docker or Postgres.
"""

from __future__ import annotations

import pytest

from backend.persistence.repositories.memory_repo import PostgresMemoryRepo
from backend.persistence.session import build_database
from backend.shared.models import MemoryEntry


@pytest.fixture
async def store(tmp_path):
    """Fresh file-backed SQLite + PostgresMemoryRepo per test.

    We use a file rather than ``:memory:`` because pytest-asyncio's
    auto mode spins a fresh event loop per function; in-memory SQLite
    handles pinned to the fixture's loop get disposed before the test
    body runs. A tmp_path file sidesteps that entirely.
    """
    database = build_database(f"sqlite+aiosqlite:///{tmp_path / 'memory.db'}")
    await database.create_all()
    try:
        yield PostgresMemoryRepo(database)
    finally:
        await database.dispose()


@pytest.mark.asyncio
class TestMemoryStore:
    async def test_load_empty(self, store):
        entries = await store.load()
        assert entries == []

    async def test_save_and_load(self, store):
        entry = MemoryEntry(
            id="INC-001", symptom="502 error",
            root_cause="Pool exhaustion", fix="Increased pool",
            vectors=["502", "pool"],
        )
        await store.save(entry)
        entries = await store.load()
        assert len(entries) == 1
        assert entries[0].id == "INC-001"

    async def test_get_relevant(self, store):
        e1 = MemoryEntry(
            id="1", symptom="502", root_cause="pool",
            fix="fix", vectors=["502", "pool"],
        )
        e2 = MemoryEntry(
            id="2", symptom="disk full", root_cause="logs",
            fix="cleanup", vectors=["disk", "space"],
        )
        await store.save(e1)
        await store.save(e2)

        relevant = await store.get_relevant(["502", "gateway"])
        assert len(relevant) == 1
        assert relevant[0].id == "1"

    async def test_get_count(self, store):
        assert await store.get_count() == 0
        await store.save(MemoryEntry(
            id="1", symptom="s", root_cause="r", fix="f", vectors=["v"]
        ))
        assert await store.get_count() == 1

    async def test_compact(self, store):
        for i in range(5):
            await store.save(MemoryEntry(
                id=str(i), symptom="s", root_cause="r",
                fix="f", vectors=["v"],
            ))
        assert await store.get_count() == 5
        summary = [MemoryEntry(
            id="summary", symptom="combined",
            root_cause="various", fix="various", vectors=["v"],
        )]
        await store.compact(summary)
        assert await store.get_count() == 1

    async def test_fingerprint(self, store):
        assert await store.get_fingerprint() == ""
        await store.set_fingerprint("Ubuntu-24.04-Nginx")
        assert await store.get_fingerprint() == "Ubuntu-24.04-Nginx"
