"""
E2E concurrency tests (CONC-*) from ops/E2E_TEST_CATALOG.md.

Covers:
- CONC-02: 10 concurrent /api/trigger calls → 10 distinct incidents, no races
- CONC-03: log storm dedup (xfail until P1.3 fingerprint-dedup)
- CONC-05: atomic memory writes under concurrency
- CONC-06: circuit-breaker record_usage thread-safety (already covered in
           test_p0_regressions.py; we add the async-concurrent variant here)
- CONC-08: orchestrator timeout → ESCALATED (xfail until P1.3)
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend.shared.models import LogEvent, MemoryEntry
from backend.tests.e2e.conftest import e2e, LiveStack


pytestmark = [e2e]


@pytest.mark.asyncio
async def test_conc02_concurrent_triggers_produce_distinct_incidents(stack: LiveStack):
    """E2E CONC-02: 10 concurrent triggers → 10 distinct incidents with unique ids."""
    async def fire(i: int):
        return await stack.orchestrator.handle_event(
            LogEvent(source_file=f"src-{i}", line_content=f"ERROR: distinct {i}")
        )

    results = await asyncio.gather(*(fire(i) for i in range(10)))
    ids = {inc.id for inc in results if inc}
    assert len(ids) == 10
    # All should have reached RESOLVED under the default resolving_llm
    assert all(inc.state.value == "resolved" for inc in results)
    # Active dict drained
    assert len(stack.orchestrator._active_incidents) == 0


@pytest.mark.xfail(strict=True, reason="P1.3: fingerprint-dedup not yet implemented")
@pytest.mark.asyncio
async def test_conc03_log_storm_deduplicates(stack: LiveStack):
    """E2E CONC-03: 50 identical log lines → 1 incident."""
    async def fire():
        return await stack.orchestrator.handle_event(
            LogEvent(source_file="same", line_content="ERROR: IDENTICAL")
        )

    await asyncio.gather(*(fire() for _ in range(50)))
    # With dedup in place:
    assert len(stack.orchestrator._resolved_incidents) == 1


@pytest.mark.asyncio
async def test_conc05_concurrent_memory_writes_are_atomic(stack: LiveStack):
    """E2E CONC-05: 20 concurrent save()s, no .tmp file leftover, all entries intact."""
    async def save(i: int):
        await stack.memory.save(
            MemoryEntry(id=f"M-{i:03d}", symptom=f"sym {i}",
                        root_cause="rc", fix="f",
                        vectors=["test"])
        )

    await asyncio.gather(*(save(i) for i in range(20)))

    # No partial writes hanging around
    tmp = Path(stack.config.memory.file_path + ".tmp")
    assert not tmp.exists(), ".tmp file leftover — atomic write invariant broken"

    # All 20 entries present
    entries = await stack.memory.load()
    assert len(entries) == 20
    assert {e.id for e in entries} == {f"M-{i:03d}" for i in range(20)}


@pytest.mark.asyncio
async def test_conc06_concurrent_circuit_breaker_record_usage(stack: LiveStack):
    """E2E CONC-06: record_usage under asyncio.gather is consistent."""
    # 40 concurrent calls each recording 10 tokens
    async def bump():
        stack.circuit_breaker.record_usage(10, 10)

    await asyncio.gather(*(bump() for _ in range(40)))

    status = stack.circuit_breaker.get_status()
    assert status["input_tokens"] == 400
    assert status["output_tokens"] == 400


@pytest.mark.xfail(strict=True, reason="P1.3: asyncio.wait_for around graph.ainvoke not yet wired")
@pytest.mark.asyncio
async def test_conc08_orchestrator_timeout_escalates():
    """E2E CONC-08: graph invocation that exceeds the timeout is ESCALATED, not hung."""
    # After P1.3 ships, this test will install a slow FakeLLMClient that
    # sleeps 10 s while ORCHESTRATOR_TIMEOUT_SECONDS=1, then asserts the
    # incident finishes as ESCALATED in ~1 s.
    assert False
