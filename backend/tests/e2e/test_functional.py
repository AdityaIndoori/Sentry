"""
E2E functional tests (FN-*) from ops/E2E_TEST_CATALOG.md.

All tests here run against the LiveStack built in conftest.py — full
orchestrator, graph, agents, tool executor, security, vault, audit log,
watcher — with only the LLM swapped for a scripted FakeLLMClient.

Tests that depend on features that have not yet shipped (Postgres
persistence, auth, SSE, OTel metrics) are marked `xfail(strict=True)`
with a `reason` pointing at the phase in `implementation_plan.md` that
will make them pass.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone

import httpx
import pytest

from backend.shared.models import (
    ActivityType,
    Incident,
    IncidentState,
    LogEvent,
)
from backend.tests.e2e.conftest import e2e, build_live_stack, LiveStack
from backend.tests.e2e.fake_llm import (
    FakeLLMClient,
    Rule,
    resolving_llm,
    false_positive_llm,
    never_resolves_llm,
    DEFAULT_TRIAGE,
    DEFAULT_DETECTIVE,
    DEFAULT_SURGEON,
    DEFAULT_VALIDATOR_RESOLVED,
    DEFAULT_VALIDATOR_UNRESOLVED,
)


pytestmark = [e2e]


# ══════════════════════════════════════════════════════════════════════
# Health / status / tools / security / config — simple API surface
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_fn01_health_endpoint(api_client):
    """E2E FN-01: health endpoint is live, returns 200, no auth required."""
    r = await api_client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.xfail(strict=True, reason="P2.3: /api/ready distinct from /api/health not yet implemented")
@pytest.mark.asyncio
async def test_fn02_readiness_distinct_from_liveness(api_client):
    """E2E FN-02: /api/ready returns 200 only when all deps reachable."""
    r = await api_client.get("/api/ready")
    assert r.status_code == 200
    body = r.json()
    # readiness semantics we want:
    assert body.get("llm_reachable") is True
    assert body.get("db_reachable") is True
    assert body.get("disk_writable") is True


@pytest.mark.asyncio
async def test_fn03_status_cold_start(api_client):
    """E2E FN-03: no active incidents on cold start."""
    r = await api_client.get("/api/status")
    assert r.status_code == 200
    body = r.json()
    assert body["active_incidents"] == 0
    assert body["resolved_total"] == 0
    assert body["circuit_breaker"]["tripped"] is False
    assert body["watcher_running"] is False


@pytest.mark.asyncio
async def test_fn15_tools_endpoint_lists_six(api_client):
    """E2E FN-15: /api/tools lists all 6 MCP tool definitions."""
    r = await api_client.get("/api/tools")
    assert r.status_code == 200
    names = {t["name"] for t in r.json()["tools"]}
    assert names == {
        "read_file", "grep_search", "fetch_docs",
        "run_diagnostics", "apply_patch", "restart_service",
    }


@pytest.mark.asyncio
async def test_fn16_security_posture(api_client):
    """E2E FN-16: /api/security shows all 5 Zero-Trust layers active."""
    r = await api_client.get("/api/security")
    assert r.status_code == 200
    zt = r.json()["zero_trust"]
    for layer in ("vault", "ai_gateway", "audit_log", "agent_throttle", "tool_registry"):
        assert zt[layer] == "active", f"layer {layer} not active"


@pytest.mark.asyncio
async def test_fn17_config_does_not_leak_secrets(api_client):
    """E2E FN-17: /api/config never exposes API keys, tokens, or DB URLs."""
    r = await api_client.get("/api/config")
    assert r.status_code == 200
    body = json.dumps(r.json()).lower()
    for banned in ("anthropic_api_key", "api_auth_token", "database_url",
                   "secret", "password", "token="):
        assert banned not in body, f"config endpoint leaked {banned!r}"


# ══════════════════════════════════════════════════════════════════════
# Orchestrator happy-path / failure-path / retry-path
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_fn04_trigger_resolves(stack: LiveStack):
    """E2E FN-04: manual trigger → full pipeline → RESOLVED, memory saved, activity trail complete."""
    event = LogEvent(
        source_file="manual",
        line_content="ERROR: postgres pool exhausted",
        timestamp=datetime.now(timezone.utc),
        matched_pattern="manual",
    )
    incident = await stack.orchestrator.handle_event(event)

    assert incident is not None
    assert incident.state == IncidentState.RESOLVED
    # Clean up from active
    assert len(stack.orchestrator._active_incidents) == 0
    # Promoted into resolved
    assert len(stack.orchestrator._resolved_incidents) == 1
    # Memory saved
    entries = await stack.memory.load()
    assert len(entries) == 1
    assert entries[0].id == incident.id

    # Activity trail — at least one phase_start and phase_complete for each
    phases_started = {a.phase for a in incident.activity_log
                      if a.activity_type == ActivityType.PHASE_START}
    assert {"triage", "diagnosis", "remediation", "verification"}.issubset(phases_started)


@pytest.mark.asyncio
async def test_fn05_triage_false_positive_no_further_phases(live_stack_factory):
    """E2E FN-05: Triage returns FALSE_POSITIVE → IDLE, no diagnosis/remediation."""
    stack = live_stack_factory(llm=false_positive_llm())
    event = LogEvent(source_file="x", line_content="minor noise")
    incident = await stack.orchestrator.handle_event(event)

    assert incident is not None
    assert incident.state == IncidentState.IDLE
    # No later phases
    phases = {a.phase for a in incident.activity_log
              if a.activity_type == ActivityType.PHASE_START}
    assert "triage" in phases
    assert "diagnosis" not in phases
    assert "remediation" not in phases
    assert "verification" not in phases
    # Memory NOT saved (only resolved incidents go to memory)
    assert len(await stack.memory.load()) == 0
    # Cleaned up from active
    assert len(stack.orchestrator._active_incidents) == 0


@pytest.mark.asyncio
async def test_fn06_retry_loop_resolves_on_second_try(live_stack_factory):
    """E2E FN-06: Validator fails once, then succeeds on retry."""
    # Script: validator returns UNRESOLVED once, then RESOLVED.
    call_count = {"validator": 0}

    async def validator_side_effect(prompt, effort, tools):
        call_count["validator"] += 1
        if call_count["validator"] == 1:
            return DEFAULT_VALIDATOR_UNRESOLVED
        return DEFAULT_VALIDATOR_RESOLVED

    llm = FakeLLMClient([
        Rule(
            predicate=lambda p, e, t: "Validator Agent for Sentry" in (p or ""),
            response={}, side_effect=validator_side_effect, name="validator-flakey",
        ),
        Rule.when_prompt_contains("Apply a fix using the available tools", response={
            **DEFAULT_SURGEON,
            "text": "FIX PROPOSED: restart\nFIX DETAILS: ok",
        }),
        Rule.when_prompt_contains("You are diagnosing a server incident", response={
            **DEFAULT_DETECTIVE,
            "text": "ROOT CAUSE: transient\nRECOMMENDED FIX: retry",
        }),
        Rule.when_prompt_contains("Triage this production error", response={
            **DEFAULT_TRIAGE,
            "text": "SEVERITY: high\nVERDICT: INVESTIGATE\nSUMMARY: retry-needed",
        }),
        Rule.default(response=DEFAULT_DETECTIVE),
    ])
    stack = live_stack_factory(llm=llm)

    event = LogEvent(source_file="x", line_content="ERROR: retry me")
    incident = await stack.orchestrator.handle_event(event)

    assert incident.state == IncidentState.RESOLVED
    assert incident.retry_count == 1  # one failed verification before success


@pytest.mark.asyncio
async def test_fn07_max_retries_escalates_and_cleans_up(live_stack_factory):
    """E2E FN-07: MAX_RETRIES exceeded → ESCALATED, removed from _active_incidents, memory NOT saved."""
    stack = live_stack_factory(llm=never_resolves_llm())

    event = LogEvent(source_file="x", line_content="ERROR: unresolvable")
    incident = await stack.orchestrator.handle_event(event)

    assert incident.state == IncidentState.ESCALATED
    assert incident.retry_count >= stack.config.security.max_retries
    # ESCALATED leak regression — must be removed
    assert len(stack.orchestrator._active_incidents) == 0
    # Not promoted to resolved either
    assert len(stack.orchestrator._resolved_incidents) == 0
    # Memory not saved
    assert len(await stack.memory.load()) == 0


@pytest.mark.asyncio
async def test_fn04_trigger_via_api(stack: LiveStack, api_client):
    """E2E FN-04 (API variant): POST /api/trigger produces a resolved incident visible in /api/incidents."""
    r = await api_client.post(
        "/api/trigger",
        json={"source": "manual", "message": "ERROR: test trigger"},
    )
    assert r.status_code == 200
    inc = r.json()["incident"]
    assert inc is not None
    assert inc["state"] == "resolved"

    r2 = await api_client.get("/api/incidents")
    assert r2.status_code == 200
    body = r2.json()
    assert len(body["resolved"]) == 1
    assert len(body["active"]) == 0


@pytest.mark.asyncio
async def test_fn13_incident_detail_has_full_activity_log(stack: LiveStack, api_client):
    """E2E FN-13: completed incident has activity log with every activity type expected."""
    # Run one incident
    r = await api_client.post("/api/trigger", json={"message": "ERROR: detail test"})
    assert r.status_code == 200
    inc = r.json()["incident"]

    # activity_log is already in the to_dict() output
    types_seen = {a["activity_type"] for a in inc["activity_log"]}
    # Phase lifecycle markers present for all 4 phases
    assert "phase_start" in types_seen
    assert "phase_complete" in types_seen
    # Decision events from routing
    assert "decision" in types_seen


# ══════════════════════════════════════════════════════════════════════
# Watcher end-to-end: file change → pipeline
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_fn08_watcher_detects_log_line_and_fires_pipeline(stack: LiveStack):
    """E2E FN-08: Watcher sees an ERROR append and the orchestrator processes it."""
    log_path = stack.root / "watched" / "app.log"
    log_path.write_text("INFO: starting\n")

    # Start watcher
    task = await stack.watcher.start()
    assert task is not None

    # Pump: dispatch events from the watcher queue to the orchestrator
    processed = []

    async def dispatcher():
        try:
            async for evt in stack.watcher.events():
                inc = await stack.orchestrator.handle_event(evt)
                processed.append(inc)
                break  # one is enough for this test
        except asyncio.CancelledError:
            pass

    dispatch_task = asyncio.create_task(dispatcher())
    try:
        # Give the watcher a cycle to settle, then append the error
        await asyncio.sleep(0.15)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write("ERROR: Connection refused on port 5432\n")

        # Wait up to 2 s for pipeline
        for _ in range(40):
            if processed:
                break
            await asyncio.sleep(0.05)
    finally:
        dispatch_task.cancel()
        await stack.watcher.stop()

    assert processed, "watcher did not fire the pipeline within 2s"
    inc = processed[0]
    assert inc is not None
    assert inc.state == IncidentState.RESOLVED


@pytest.mark.asyncio
async def test_fn09_watcher_ignores_non_matching_lines(stack: LiveStack):
    """E2E FN-09: INFO lines do not create incidents."""
    log_path = stack.root / "watched" / "app.log"
    log_path.write_text("")

    task = await stack.watcher.start()
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write("INFO: starting up\n")
            f.write("DEBUG: nothing of note\n")

        await asyncio.sleep(0.25)  # multiple poll cycles
        assert stack.watcher._event_queue.qsize() == 0
    finally:
        await stack.watcher.stop()


@pytest.mark.skipif(
    os.name == "nt",
    reason="logrotate-style rename requires POSIX rename-on-open semantics; "
           "truncate-in-place is covered by FN-11 (test_fn11_watcher_handles_truncate_in_place)",
)
@pytest.mark.asyncio
async def test_fn10_watcher_detects_rotation_via_inode(stack: LiveStack):
    """E2E FN-10: logrotate-style rename → new file, inode change detected, new errors still fire.

    POSIX-only: on NTFS you cannot rename a file that's currently open by another
    process without Admin + MOVEFILE_DELAY_UNTIL_REBOOT tricks, so this test is
    skipped on Windows and the truncate-in-place behavior is covered by FN-11.
    """
    log_path = stack.root / "watched" / "app.log"
    log_path.write_text("ERROR: old error\n")

    task = await stack.watcher.start()
    try:
        # Let the first error be seen and drained
        for _ in range(20):
            if stack.watcher._event_queue.qsize() > 0:
                await stack.watcher._event_queue.get()
                break
            await asyncio.sleep(0.05)

        # Rotate: move aside and recreate
        rotated = stack.root / "watched" / "app.log.1"
        os.rename(log_path, rotated)
        log_path.write_text("ERROR: after rotate\n")

        # Wait for the new event
        seen = None
        for _ in range(40):
            if stack.watcher._event_queue.qsize() > 0:
                seen = await stack.watcher._event_queue.get()
                break
            await asyncio.sleep(0.05)
        assert seen is not None, "watcher didn't see post-rotation error"
        assert "after rotate" in seen.line_content
    finally:
        await stack.watcher.stop()


@pytest.mark.asyncio
async def test_fn11_watcher_handles_truncate_in_place(stack: LiveStack):
    """E2E FN-11: truncate-in-place (size shrinks) → offset resets, new errors fire."""
    log_path = stack.root / "watched" / "app.log"
    log_path.write_text("ERROR: early error\n" * 10)  # large-ish

    task = await stack.watcher.start()
    try:
        # Drain whatever comes first
        await asyncio.sleep(0.15)
        while stack.watcher._event_queue.qsize() > 0:
            await stack.watcher._event_queue.get()

        # Truncate in place
        log_path.write_text("ERROR: after truncate\n")

        seen = None
        for _ in range(40):
            if stack.watcher._event_queue.qsize() > 0:
                seen = await stack.watcher._event_queue.get()
                break
            await asyncio.sleep(0.05)
        assert seen is not None
        assert "after truncate" in seen.line_content
    finally:
        await stack.watcher.stop()


# ══════════════════════════════════════════════════════════════════════
# Tools — basic positive paths
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_fn23_read_file_happy_path(stack: LiveStack):
    """E2E FN-23 companion: read_file returns contents of a known source file."""
    from backend.shared.models import ToolCall
    result = await stack.tools.execute(
        ToolCall(tool_name="read_file", arguments={"path": "config/db.py"})
    )
    assert result.success is True
    assert "DB_HOST" in (result.output or "")


@pytest.mark.asyncio
async def test_fn_storm_dedup(stack: LiveStack):
    """E2E CONC-03 preview: 10 identical triggers in rapid succession yield 1 incident after dedup.

    Serial cousin of CONC-03 — verifies the dedup cache persists across
    sequential calls (not just within a single ``asyncio.gather``).
    """
    for _ in range(10):
        await stack.orchestrator.handle_event(
            LogEvent(source_file="x", line_content="ERROR: the same error")
        )
    # With P1.3 dedup: only the first event is processed; the other 9
    # are short-circuited.
    assert len(stack.orchestrator._resolved_incidents) == 1


# ══════════════════════════════════════════════════════════════════════
# Memory
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_fn14_memory_returns_recent_entries(stack: LiveStack, api_client):
    """E2E FN-14: /api/memory returns most-recent entries."""
    # Trigger a resolved incident
    await api_client.post("/api/trigger", json={"message": "ERROR: mem test"})

    r = await api_client.get("/api/memory")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1
    assert len(body["entries"]) == 1


@pytest.mark.xfail(strict=True, reason="P1.1: startup must populate system_fingerprint on memory")
@pytest.mark.asyncio
async def test_fn22_fingerprint_populated_on_startup(stack: LiveStack):
    """E2E FN-22: MemoryStore.get_fingerprint() is non-empty after startup."""
    fp = await stack.memory.get_fingerprint()
    assert fp, "memory fingerprint should be set at startup from Service Awareness"
