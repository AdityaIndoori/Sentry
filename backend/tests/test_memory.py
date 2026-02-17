"""
TDD tests for JSONMemoryStore.
"""

import pytest
from backend.memory.store import JSONMemoryStore
from backend.shared.models import MemoryEntry


@pytest.fixture
def store(memory_config):
    return JSONMemoryStore(memory_config)


@pytest.mark.asyncio
class TestJSONMemoryStore:
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
