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


@pytest.mark.asyncio
async def test_conc03_log_storm_deduplicates(stack: LiveStack):
    """E2E CONC-03: 50 identical log lines → 1 incident.

    P1.3 fingerprint-dedup: the first event is processed normally and
    resolves; the remaining 49 hit
    ``Orchestrator._is_duplicate`` within the 60-second window and
    short-circuit before any LLM spend. Net result is exactly one
    resolved incident.
    """
    async def fire():
        return await stack.orchestrator.handle_event(
            LogEvent(source_file="same", line_content="ERROR: IDENTICAL")
        )

    results = await asyncio.gather(*(fire() for _ in range(50)))
    # Exactly one resolved incident — the first shot through; the
    # other 49 returned None (dedup hit).
    non_none = [r for r in results if r is not None]
    assert len(non_none) == 1, f"expected 1 non-dedup result, got {len(non_none)}"
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


@pytest.mark.asyncio
async def test_conc08_orchestrator_timeout_escalates(live_stack_factory):
    """E2E CONC-08: graph invocation that exceeds the timeout is ESCALATED, not hung.

    P1.3: ``Orchestrator.handle_event`` wraps ``graph.ainvoke`` in
    ``asyncio.wait_for(..., timeout=orchestrator_timeout_seconds)``.
    We install a Triage-phase LLM handler that sleeps 5 s while the
    orchestrator timeout is 1 s, then assert the incident finished as
    ESCALATED in well under 2 s (not the full 5).
    """
    import time as _time

    # Slow LLM: Triage stalls for 5 seconds, all other prompts resolve.
    async def slow_triage(prompt, effort, tools):
        await asyncio.sleep(5.0)
        return {
            "text": "SEVERITY: high\nVERDICT: INVESTIGATE\nSUMMARY: too-slow",
            "tool_calls": [],
            "usage": {"input_tokens": 0, "output_tokens": 0},
        }

    from backend.tests.e2e.fake_llm import (
        FakeLLMClient, Rule,
        DEFAULT_TRIAGE, DEFAULT_DETECTIVE, DEFAULT_SURGEON,
        DEFAULT_VALIDATOR_RESOLVED,
    )

    llm = FakeLLMClient([
        Rule(
            predicate=lambda p, e, t: "Triage this production error" in (p or ""),
            response={}, side_effect=slow_triage, name="triage-slow",
        ),
        Rule.when_prompt_contains("Validator Agent for Sentry",
                                  response=DEFAULT_VALIDATOR_RESOLVED),
        Rule.when_prompt_contains("Apply a fix using the available tools",
                                  response=DEFAULT_SURGEON),
        Rule.when_prompt_contains("You are diagnosing a server incident",
                                  response=DEFAULT_DETECTIVE),
        Rule.default(response=DEFAULT_DETECTIVE),
    ])
    stack = live_stack_factory(llm=llm)

    # Dial the orchestrator timeout down to 1 second for this test.
    stack.orchestrator._orch_timeout = 1

    event = LogEvent(source_file="x", line_content="ERROR: hung agent")

    t0 = _time.monotonic()
    incident = await stack.orchestrator.handle_event(event)
    elapsed = _time.monotonic() - t0

    from backend.shared.models import IncidentState
    assert incident is not None
    assert incident.state == IncidentState.ESCALATED, (
        f"expected ESCALATED after timeout, got {incident.state}"
    )
    # Must have cut the wait short — nowhere near the 5 s triage sleep.
    assert elapsed < 2.5, f"handle_event took {elapsed:.2f}s (timeout wrapper didn't fire)"
    # Active dict drained.
    assert len(stack.orchestrator._active_incidents) == 0
