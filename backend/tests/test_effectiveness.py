"""
Tests for the effectiveness upgrades:

1. Canonical normalized fingerprinting (backend/shared/fingerprint.py)
   — log-storm lines that differ only in timestamps/PIDs/IPs dedup.
2. Keyword extraction for memory retrieval vectors.
3. Escalation cooldown — a fingerprint that just ESCALATED is suppressed.
4. Real memory compaction — duplicates merged, store trimmed.
5. Escalation webhook notifier — fires on ESCALATED, skips RESOLVED by
   default, never raises into the orchestrator hot path.
6. Per-incident cost accounting — incident.cost_usd reflects token spend.
7. Retry feedback + memory hints plumbed into Detective/Surgeon prompts;
   remediation evidence plumbed into the Validator prompt.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.orchestrator.engine import Orchestrator
from backend.shared.circuit_breaker import CostCircuitBreaker
from backend.shared.config import (
    AppConfig,
    MemoryConfig,
    SecurityConfig,
    SentryMode,
    WatcherConfig,
)
from backend.shared.fingerprint import (
    compute_fingerprint,
    extract_keywords,
    normalize_log_line,
)
from backend.shared.models import (
    Incident,
    IncidentState,
    LogEvent,
    MemoryEntry,
)

# ═══════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════


def _make_config(project_root: str = "/tmp/test", max_compact: int = 50) -> AppConfig:
    return AppConfig(
        security=SecurityConfig(mode=SentryMode.AUDIT, project_root=project_root),
        memory=MemoryConfig(
            file_path=f"{project_root}/mem.json",
            max_incidents_before_compaction=max_compact,
        ),
        watcher=WatcherConfig(watch_paths=()),
        service_source_path=project_root,
    )


def _build_orchestrator(graph_side_effect, *, config: AppConfig | None = None,
                        memory: AsyncMock | None = None, **orch_kwargs) -> Orchestrator:
    """Build an Orchestrator with a scripted graph (no LLM)."""
    mock_graph = AsyncMock()
    mock_graph.ainvoke = AsyncMock(side_effect=graph_side_effect)
    mock_builder = MagicMock()
    mock_builder.build.return_value = mock_graph

    mock_registry = MagicMock()
    mock_registry.has_context.return_value = False
    mock_registry.build_prompt_context.return_value = ""

    mem = memory or AsyncMock()
    if memory is None:
        mem.save = AsyncMock()
        mem.load = AsyncMock(return_value=[])
        mem.get_count = AsyncMock(return_value=0)
        mem.system_fingerprint = ""

    with patch("backend.orchestrator.engine.ServiceRegistry", return_value=mock_registry), \
         patch("backend.orchestrator.engine.IncidentGraphBuilder", return_value=mock_builder):
        return Orchestrator(
            config or _make_config(),
            AsyncMock(),
            AsyncMock(),
            mem,
            CostCircuitBreaker(max_cost_usd=5.0),
            **orch_kwargs,
        )


def _escalate(state):
    state["incident"].state = IncidentState.ESCALATED
    return {"incident": state["incident"]}


def _resolve(state):
    state["incident"].state = IncidentState.RESOLVED
    state["incident"].root_cause = "rc"
    state["incident"].fix_applied = "fx"
    return {"incident": state["incident"]}


# ═══════════════════════════════════════════════════════════════
# 1. Normalized fingerprinting
# ═══════════════════════════════════════════════════════════════


class TestNormalizedFingerprint:
    def test_timestamps_normalize_away(self):
        a = normalize_log_line("ERROR [2026-01-02T10:11:12] worker died")
        b = normalize_log_line("ERROR [2026-06-30T23:59:59] worker died")
        assert a == b

    def test_pids_ports_request_ids_normalize_away(self):
        a = normalize_log_line("ERROR worker 4123 failed req=a1b2c3d4e5f60718 from 10.0.0.5")
        b = normalize_log_line("ERROR worker 9876 failed req=ffeeddccbbaa9988 from 192.168.1.99")
        assert a == b

    def test_distinct_errors_stay_distinct(self):
        a = normalize_log_line("ERROR: connection refused")
        b = normalize_log_line("ERROR: disk full")
        assert a != b

    def test_fingerprint_collapses_log_storm_variants(self):
        fp1 = compute_fingerprint("app.log", "(?i)error",
                                  "2026-01-01 10:00:01 ERROR conn refused pid 111")
        fp2 = compute_fingerprint("app.log", "(?i)error",
                                  "2026-01-01 10:00:02 ERROR conn refused pid 222")
        assert fp1 == fp2

    def test_fingerprint_distinguishes_source_files(self):
        fp1 = compute_fingerprint("a.log", "(?i)error", "ERROR boom")
        fp2 = compute_fingerprint("b.log", "(?i)error", "ERROR boom")
        assert fp1 != fp2

    def test_engine_and_repo_fingerprints_agree(self):
        """The orchestrator and persistence layer must never drift."""
        from backend.persistence.repositories.incident_repo import (
            compute_fingerprint as repo_fp,
        )
        event = LogEvent(
            source_file="x.log",
            line_content="ERROR 2026-01-01T00:00:00 conn refused pid 42",
            matched_pattern="(?i)error",
        )
        assert Orchestrator._compute_event_fingerprint(event) == repo_fp(event)

    def test_empty_line_is_stable(self):
        assert normalize_log_line("") == ""
        assert compute_fingerprint("a", "p", "") == compute_fingerprint("a", "p", "")


# ═══════════════════════════════════════════════════════════════
# 2. Keyword extraction
# ═══════════════════════════════════════════════════════════════


class TestKeywordExtraction:
    def test_drops_stopwords_and_noise(self):
        kws = extract_keywords("ERROR: Connection refused on the port 5432")
        assert "error" not in kws
        assert "the" not in kws
        assert "connection" in kws
        assert "refused" in kws
        assert "5432" in kws

    def test_keeps_status_codes(self):
        kws = extract_keywords("upstream returned 502 bad gateway")
        assert "502" in kws
        assert "gateway" in kws

    def test_dedup_and_cap(self):
        kws = extract_keywords("redis redis redis timeout timeout alpha beta "
                               "gamma delta epsilon zeta eta theta", k=5)
        assert len(kws) == 5
        assert kws.count("redis") == 1

    def test_empty_input(self):
        assert extract_keywords("") == []


# ═══════════════════════════════════════════════════════════════
# 3. Escalation cooldown
# ═══════════════════════════════════════════════════════════════


class TestEscalationCooldown:
    @pytest.mark.asyncio
    async def test_escalated_fingerprint_is_suppressed(self):
        orch = _build_orchestrator(_escalate, escalation_cooldown_seconds=300,
                                   dedup_window_seconds=0)
        event = LogEvent(source_file="x", line_content="ERROR: unfixable")
        first = await orch.handle_event(event)
        assert first is not None
        assert first.state == IncidentState.ESCALATED

        # Same fingerprint again → suppressed (no new incident, no LLM spend).
        second = await orch.handle_event(
            LogEvent(source_file="x", line_content="ERROR: unfixable")
        )
        assert second is None

    @pytest.mark.asyncio
    async def test_resolved_fingerprint_is_not_suppressed(self):
        orch = _build_orchestrator(_resolve, escalation_cooldown_seconds=300,
                                   dedup_window_seconds=0)
        first = await orch.handle_event(
            LogEvent(source_file="x", line_content="ERROR: fixable")
        )
        assert first.state == IncidentState.RESOLVED
        # Resolved fingerprints are NOT in cooldown; only dedup (disabled
        # here) would stop re-processing.
        second = await orch.handle_event(
            LogEvent(source_file="x", line_content="ERROR: fixable")
        )
        assert second is not None

    @pytest.mark.asyncio
    async def test_cooldown_expires(self):
        orch = _build_orchestrator(_escalate, escalation_cooldown_seconds=300,
                                   dedup_window_seconds=0)
        event = LogEvent(source_file="x", line_content="ERROR: unfixable")
        await orch.handle_event(event)

        # Manufacture expiry by back-dating the recorded escalation.
        fp_key = next(iter(orch._escalated_fingerprints))
        orch._escalated_fingerprints[fp_key] -= 10_000

        third = await orch.handle_event(
            LogEvent(source_file="x", line_content="ERROR: unfixable")
        )
        assert third is not None  # fresh attempt allowed

    @pytest.mark.asyncio
    async def test_cooldown_disabled_with_zero(self):
        orch = _build_orchestrator(_escalate, escalation_cooldown_seconds=0,
                                   dedup_window_seconds=0)
        await orch.handle_event(LogEvent(source_file="x", line_content="ERROR: e"))
        again = await orch.handle_event(LogEvent(source_file="x", line_content="ERROR: e"))
        assert again is not None  # suppression off

    @pytest.mark.asyncio
    async def test_different_fingerprint_not_suppressed(self):
        orch = _build_orchestrator(_escalate, escalation_cooldown_seconds=300,
                                   dedup_window_seconds=0)
        await orch.handle_event(LogEvent(source_file="x", line_content="ERROR: alpha-failure"))
        other = await orch.handle_event(
            LogEvent(source_file="x", line_content="ERROR: beta-breakage")
        )
        assert other is not None


# ═══════════════════════════════════════════════════════════════
# 4. Memory compaction
# ═══════════════════════════════════════════════════════════════


class TestMemoryCompaction:
    @pytest.mark.asyncio
    async def test_compaction_merges_duplicates_and_trims(self):
        entries = [
            MemoryEntry(id=f"INC-{i}", symptom=f"symptom {i}",
                        root_cause="db down", fix="restart db",
                        vectors=[f"tok{i}"])
            for i in range(8)
        ] + [
            MemoryEntry(id="INC-U1", symptom="unique 1", root_cause="rc1", fix="f1",
                        vectors=["u1"]),
            MemoryEntry(id="INC-U2", symptom="unique 2", root_cause="rc2", fix="f2",
                        vectors=["u2"]),
        ]
        mem = AsyncMock()
        mem.load = AsyncMock(return_value=entries)
        mem.get_count = AsyncMock(return_value=len(entries))
        mem.save = AsyncMock()
        mem.compact = AsyncMock()
        mem.system_fingerprint = ""

        orch = _build_orchestrator(_resolve, config=_make_config(max_compact=5),
                                   memory=mem)
        await orch._compact_memory()

        mem.compact.assert_awaited_once()
        compacted = mem.compact.call_args[0][0]
        # 8 duplicates merged into 1, plus 2 unique = 3 (≤ threshold 5).
        assert len(compacted) == 3
        # Merged entry is the NEWEST duplicate, vectors unioned.
        dup = next(e for e in compacted if e.root_cause == "db down")
        assert dup.id == "INC-7"
        assert set(dup.vectors) == {f"tok{i}" for i in range(8)}

    @pytest.mark.asyncio
    async def test_compaction_trims_when_all_unique(self):
        entries = [
            MemoryEntry(id=f"INC-{i}", symptom=f"s{i}", root_cause=f"rc{i}",
                        fix=f"f{i}", vectors=[f"v{i}"])
            for i in range(10)
        ]
        mem = AsyncMock()
        mem.load = AsyncMock(return_value=entries)
        mem.compact = AsyncMock()
        mem.system_fingerprint = ""

        orch = _build_orchestrator(_resolve, config=_make_config(max_compact=4),
                                   memory=mem)
        await orch._compact_memory()

        compacted = mem.compact.call_args[0][0]
        assert len(compacted) == 4
        # Recency wins — the newest 4 survive.
        assert [e.id for e in compacted] == ["INC-6", "INC-7", "INC-8", "INC-9"]

    @pytest.mark.asyncio
    async def test_no_compaction_below_threshold(self):
        mem = AsyncMock()
        mem.load = AsyncMock(return_value=[
            MemoryEntry(id="A", symptom="s", root_cause="r", fix="f")
        ])
        mem.compact = AsyncMock()
        mem.system_fingerprint = ""

        orch = _build_orchestrator(_resolve, config=_make_config(max_compact=5),
                                   memory=mem)
        await orch._compact_memory()
        mem.compact.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_save_to_memory_triggers_compaction_over_threshold(self):
        mem = AsyncMock()
        mem.save = AsyncMock()
        mem.get_count = AsyncMock(return_value=10)  # over threshold of 5
        mem.load = AsyncMock(return_value=[
            MemoryEntry(id=f"I{i}", symptom=f"s{i}", root_cause="same", fix="same")
            for i in range(10)
        ])
        mem.compact = AsyncMock()
        mem.system_fingerprint = ""

        orch = _build_orchestrator(_resolve, config=_make_config(max_compact=5),
                                   memory=mem)
        incident = Incident(id="INC-T", symptom="boom", root_cause="rc", fix_applied="fx")
        await orch._save_to_memory(incident)
        mem.compact.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_memory_vectors_use_keyword_extraction(self):
        mem = AsyncMock()
        mem.save = AsyncMock()
        mem.get_count = AsyncMock(return_value=0)
        mem.system_fingerprint = ""

        orch = _build_orchestrator(_resolve, memory=mem)
        incident = Incident(
            id="INC-K",
            symptom="ERROR: Connection refused on port 5432",
            root_cause="rc", fix_applied="fx",
        )
        await orch._save_to_memory(incident)
        saved = mem.save.call_args[0][0]
        assert "connection" in saved.vectors
        assert "5432" in saved.vectors
        assert "error" not in saved.vectors  # stop-word dropped


# ═══════════════════════════════════════════════════════════════
# 5. Webhook notifier
# ═══════════════════════════════════════════════════════════════


class TestWebhookNotifier:
    def test_should_notify_matrix(self):
        from backend.services.notifier import WebhookNotifier
        n = WebhookNotifier("http://example.invalid/hook")
        assert n.should_notify("escalated") is True
        assert n.should_notify("resolved") is False
        assert n.should_notify("idle") is False

        n2 = WebhookNotifier("http://example.invalid/hook", notify_resolved=True)
        assert n2.should_notify("resolved") is True

    @pytest.mark.asyncio
    async def test_notify_escalated_posts_payload(self):
        from backend.services.notifier import WebhookNotifier
        n = WebhookNotifier("http://example.invalid/hook")
        incident = Incident(id="INC-N1", symptom="boom",
                            state=IncidentState.ESCALATED)

        sent: list[dict] = []

        async def fake_deliver(payload):
            sent.append(payload)

        with patch.object(n, "_deliver", side_effect=fake_deliver):
            n.notify_incident(incident)
            # Drain the scheduled task.
            await asyncio.sleep(0.05)

        assert len(sent) == 1
        assert sent[0]["incident"]["id"] == "INC-N1"
        assert sent[0]["incident"]["state"] == "escalated"
        assert "🚨" in sent[0]["text"]

    @pytest.mark.asyncio
    async def test_notify_resolved_skipped_by_default(self):
        from backend.services.notifier import WebhookNotifier
        n = WebhookNotifier("http://example.invalid/hook")
        incident = Incident(id="INC-N2", symptom="ok", state=IncidentState.RESOLVED)

        with patch.object(n, "_deliver", new=AsyncMock()) as deliver:
            n.notify_incident(incident)
            await asyncio.sleep(0.02)
            deliver.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delivery_failure_never_raises(self):
        from backend.services.notifier import WebhookNotifier
        # Unroutable URL — httpx will fail fast; the error must be swallowed.
        n = WebhookNotifier("http://127.0.0.1:1/hook", timeout_seconds=0.2)
        incident = Incident(id="INC-N3", symptom="x", state=IncidentState.ESCALATED)
        n.notify_incident(incident)  # must not raise
        await n.close()
        assert n.error_count >= 0  # stats object intact

    @pytest.mark.asyncio
    async def test_orchestrator_calls_notifier_on_escalation(self):
        notifier = MagicMock()
        orch = _build_orchestrator(_escalate, notifier=notifier,
                                   dedup_window_seconds=0,
                                   escalation_cooldown_seconds=0)
        await orch.handle_event(LogEvent(source_file="x", line_content="ERROR: n"))
        notifier.notify_incident.assert_called_once()
        incident_arg = notifier.notify_incident.call_args[0][0]
        assert incident_arg.state == IncidentState.ESCALATED

    @pytest.mark.asyncio
    async def test_deliver_success_increments_sent(self):
        from backend.services.notifier import WebhookNotifier
        n = WebhookNotifier("http://hook.invalid/x")

        class _FakeResp:
            status_code = 200

        class _FakeClient:
            def __init__(self, *a, **kw): ...
            async def __aenter__(self):
                return self
            async def __aexit__(self, *exc):
                return False
            async def post(self, url, json=None):
                return _FakeResp()

        with patch("httpx.AsyncClient", _FakeClient):
            await n._deliver({"incident": {"id": "I1"}})
        assert n.sent_count == 1
        assert n.error_count == 0

    @pytest.mark.asyncio
    async def test_deliver_http_error_increments_error(self):
        from backend.services.notifier import WebhookNotifier
        n = WebhookNotifier("http://hook.invalid/x")

        class _FakeResp:
            status_code = 500

        class _FakeClient:
            def __init__(self, *a, **kw): ...
            async def __aenter__(self):
                return self
            async def __aexit__(self, *exc):
                return False
            async def post(self, url, json=None):
                return _FakeResp()

        with patch("httpx.AsyncClient", _FakeClient):
            await n._deliver({"incident": {"id": "I2"}})
        assert n.error_count == 1
        assert n.sent_count == 0

    @pytest.mark.asyncio
    async def test_close_with_no_inflight_returns_fast(self):
        from backend.services.notifier import WebhookNotifier
        n = WebhookNotifier("http://hook.invalid/x")
        await n.close()  # no pending tasks — must not hang or raise

    def test_notify_without_running_loop_uses_inline_path(self):
        """Sync context (no event loop) → inline asyncio.run delivery."""
        from backend.services.notifier import WebhookNotifier
        n = WebhookNotifier("http://hook.invalid/x")
        incident = Incident(id="INC-SYNC", symptom="x",
                            state=IncidentState.ESCALATED)
        with patch.object(n, "_deliver", new=AsyncMock()) as deliver:
            n.notify_incident(incident)  # no running loop in sync test
            deliver.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_orchestrator_notifier_exception_is_swallowed(self):
        notifier = MagicMock()
        notifier.notify_incident.side_effect = RuntimeError("webhook exploded")
        orch = _build_orchestrator(_resolve, notifier=notifier,
                                   dedup_window_seconds=0)
        result = await orch.handle_event(
            LogEvent(source_file="x", line_content="ERROR: ok")
        )
        assert result is not None
        assert result.state == IncidentState.RESOLVED  # hot path unharmed


# ═══════════════════════════════════════════════════════════════
# 5b. New Prometheus counters (no-op safe, real when lib installed)
# ═══════════════════════════════════════════════════════════════


class TestNewMetricsCounters:
    def test_new_helpers_never_raise(self):
        from backend.shared import metrics
        # Safe both with and without prometheus_client installed.
        metrics.inc_event_deduped()
        metrics.inc_event_suppressed()
        metrics.inc_notification(success=True)
        metrics.inc_notification(success=False)
        metrics.inc_memory_compaction()

    def test_new_counters_appear_in_exposition(self):
        from backend.shared import metrics
        if not metrics.is_available():
            pytest.skip("prometheus_client not installed")
        metrics.inc_event_deduped()
        metrics.inc_event_suppressed()
        metrics.inc_notification(success=True)
        metrics.inc_memory_compaction()
        body, _ctype = metrics.render_metrics()
        text = body.decode("utf-8")
        assert "sentry_events_deduped_total" in text
        assert "sentry_events_suppressed_total" in text
        assert "sentry_notifications_total" in text
        assert "sentry_memory_compactions_total" in text


# ═══════════════════════════════════════════════════════════════
# 5c. Settings knobs (env fallback path)
# ═══════════════════════════════════════════════════════════════


class TestEffectivenessSettings:
    def test_defaults(self):
        from backend.shared.settings import Settings
        s = Settings()
        assert s.dedup_window_seconds == 60
        assert s.escalation_cooldown_seconds == 1800
        assert s.notify_webhook_url == ""
        assert s.notify_on_resolved is False

    def test_env_fallback_reads_new_knobs(self):
        import os

        from backend.shared.settings import _build_settings_from_env

        env = {
            "DEDUP_WINDOW_SECONDS": "120",
            "ESCALATION_COOLDOWN_SECONDS": "600",
            "NOTIFY_WEBHOOK_URL": "http://hooks.example/x",
            "NOTIFY_ON_RESOLVED": "true",
        }
        with patch.dict(os.environ, env):
            s = _build_settings_from_env()
        assert s.dedup_window_seconds == 120
        assert s.escalation_cooldown_seconds == 600
        assert s.notify_webhook_url == "http://hooks.example/x"
        assert s.notify_on_resolved is True

    def test_factory_wires_notifier_when_url_set(self, tmp_path):
        from dataclasses import replace as dc_replace

        from backend.shared.factory import build_container
        from backend.shared.settings import Settings
        settings = Settings(
            memory_file_path=str(tmp_path / "data" / "mem.json"),
            audit_log_path=str(tmp_path / "data" / "audit.jsonl"),
            watch_paths=(),
            notify_webhook_url="http://hooks.example/sentry",
        )
        settings = dc_replace(settings)
        container = build_container(settings, llm_override=AsyncMock())
        try:
            assert container.notifier is not None
            assert container.orchestrator._notifier is container.notifier
            assert container.orchestrator._escalation_cooldown == 1800
        finally:
            asyncio.get_event_loop().run_until_complete(container.shutdown()) \
                if not asyncio.get_event_loop().is_running() else None

    def test_factory_skips_notifier_when_url_empty(self, tmp_path):
        from backend.shared.factory import build_container
        from backend.shared.settings import Settings
        settings = Settings(
            memory_file_path=str(tmp_path / "data" / "mem.json"),
            audit_log_path=str(tmp_path / "data" / "audit.jsonl"),
            watch_paths=(),
        )
        container = build_container(settings, llm_override=AsyncMock())
        assert container.notifier is None


# ═══════════════════════════════════════════════════════════════
# 5d. Verification schema honors the explicit RESOLVED: line
# ═══════════════════════════════════════════════════════════════


class TestVerificationExplicitParse:
    def test_resolved_false_is_false(self):
        from backend.orchestrator.schemas import VerificationResult
        r = VerificationResult.parse_safe(
            "RESOLVED: false\nREASON: error still present in logs"
        )
        assert r.resolved is False
        assert "still present" in r.reason

    def test_resolved_true_is_true(self):
        from backend.orchestrator.schemas import VerificationResult
        r = VerificationResult.parse_safe("RESOLVED: true\nREASON: fix verified")
        assert r.resolved is True
        assert r.reason == "fix verified"

    def test_explicit_line_beats_keyword_heuristics(self):
        from backend.orchestrator.schemas import VerificationResult
        # "fixed" appears but the explicit line says false → false.
        r = VerificationResult.parse_safe(
            "RESOLVED: false\nREASON: the patch claims fixed but tests fail"
        )
        assert r.resolved is False

    def test_freetext_fallback_still_works(self):
        from backend.orchestrator.schemas import VerificationResult
        assert VerificationResult.parse_safe("The issue is fixed.").resolved is True
        assert VerificationResult.parse_safe("Still broken, not fixed.").resolved is False


# ═══════════════════════════════════════════════════════════════
# 6. Per-incident cost accounting
# ═══════════════════════════════════════════════════════════════


class TestPerIncidentCost:
    def test_track_cost_attributes_to_incident(self):
        from backend.orchestrator.graph import IncidentGraphBuilder
        builder = IncidentGraphBuilder(
            _make_config(), AsyncMock(), AsyncMock(), AsyncMock(),
            CostCircuitBreaker(max_cost_usd=5.0),
        )
        incident = Incident(id="INC-C", symptom="x")
        builder._track_cost({"input_tokens": 1000, "output_tokens": 1000}, incident)
        # 1k input @ .015 + 1k output @ .075 = 0.09
        assert incident.cost_usd == pytest.approx(0.09)

    def test_track_cost_accumulates(self):
        from backend.orchestrator.graph import IncidentGraphBuilder
        builder = IncidentGraphBuilder(
            _make_config(), AsyncMock(), AsyncMock(), AsyncMock(),
            CostCircuitBreaker(max_cost_usd=5.0),
        )
        incident = Incident(id="INC-C2", symptom="x")
        builder._track_cost({"input_tokens": 1000, "output_tokens": 0}, incident)
        builder._track_cost({"input_tokens": 1000, "output_tokens": 0}, incident)
        assert incident.cost_usd == pytest.approx(0.03)

    def test_track_cost_without_incident_still_records_cb(self):
        from backend.orchestrator.graph import IncidentGraphBuilder
        cb = CostCircuitBreaker(max_cost_usd=5.0)
        builder = IncidentGraphBuilder(
            _make_config(), AsyncMock(), AsyncMock(), AsyncMock(), cb,
        )
        builder._track_cost({"input_tokens": 1000, "output_tokens": 500})
        assert cb.current_cost > 0


# ═══════════════════════════════════════════════════════════════
# 7. Context plumbing: hints / feedback / evidence reach the prompts
# ═══════════════════════════════════════════════════════════════


def _llm_with(text: str) -> AsyncMock:
    llm = AsyncMock()
    llm.analyze = AsyncMock(return_value={
        "text": text, "tool_calls": [], "thinking": "",
        "input_tokens": 10, "output_tokens": 5, "error": None,
    })
    return llm


def _zero_trust(tmp_path):
    from backend.shared.agent_throttle import AgentThrottle
    from backend.shared.ai_gateway import AIGateway
    from backend.shared.tool_registry import create_default_registry
    from backend.shared.vault import LocalVault
    return {
        "vault": LocalVault(master_secret="t"),
        "gateway": AIGateway(),
        "throttle": AgentThrottle(max_actions_per_minute=50),
        "registry": create_default_registry(),
    }


class TestContextPlumbing:
    @pytest.mark.asyncio
    async def test_detective_prompt_includes_hints_and_feedback(self, tmp_path):
        from backend.agents.detective_agent import DetectiveAgent
        zt = _zero_trust(tmp_path)
        llm = _llm_with("ROOT CAUSE: x\nRECOMMENDED FIX: y")
        tools = AsyncMock()
        tools.get_tool_definitions = MagicMock(return_value=[])
        agent = DetectiveAgent(
            vault=zt["vault"], llm=llm, tools=tools,
            registry=zt["registry"], gateway=zt["gateway"], throttle=zt["throttle"],
        )
        incident = Incident(id="INC-D", symptom="redis timeout")
        await agent.run(
            incident,
            memory_hints=[{"symptom": "redis timeout", "root_cause": "maxmemory",
                           "fix": "raise maxmemory to 2gb"}],
            retry_feedback="PREVIOUS ATTEMPT (#1) FAILED VERIFICATION.",
        )
        prompt = llm.analyze.call_args[1].get("prompt") or llm.analyze.call_args[0][0]
        assert "maxmemory" in prompt
        assert "raise maxmemory to 2gb" in prompt
        assert "FAILED VERIFICATION" in prompt

    @pytest.mark.asyncio
    async def test_surgeon_prompt_includes_hints_and_feedback(self, tmp_path):
        from backend.agents.surgeon_agent import SurgeonAgent
        zt = _zero_trust(tmp_path)
        llm = _llm_with("FIX PROPOSED: bump maxmemory")
        tools = AsyncMock()
        tools.get_tool_definitions = MagicMock(return_value=[])
        config = _make_config()
        agent = SurgeonAgent(
            vault=zt["vault"], llm=llm, tools=tools,
            registry=zt["registry"], gateway=zt["gateway"], throttle=zt["throttle"],
            config=config,
        )
        incident = Incident(id="INC-S", symptom="redis timeout", root_cause="maxmemory")
        await agent.run(
            incident,
            memory_hints=[{"root_cause": "maxmemory", "fix": "raise maxmemory"}],
            retry_feedback="Do NOT repeat the same fix.",
        )
        prompt = llm.analyze.call_args[1].get("prompt") or llm.analyze.call_args[0][0]
        assert "raise maxmemory" in prompt
        assert "Do NOT repeat the same fix." in prompt

    @pytest.mark.asyncio
    async def test_validator_prompt_includes_remediation_evidence(self, tmp_path):
        from backend.agents.validator_agent import ValidatorAgent
        zt = _zero_trust(tmp_path)
        llm = _llm_with("RESOLVED: true\nREASON: patch applied and restarted")
        agent = ValidatorAgent(vault=zt["vault"], llm=llm, gateway=zt["gateway"])
        incident = Incident(id="INC-V", symptom="boom", fix_applied="patched")
        await agent.run(
            incident,
            remediation_evidence="- apply_patch: success=True audit_only=False output=ok",
        )
        prompt = llm.analyze.call_args[1].get("prompt") or llm.analyze.call_args[0][0]
        assert "apply_patch: success=True" in prompt

    @pytest.mark.asyncio
    async def test_verification_failure_sets_retry_feedback_in_state(self, tmp_path):
        """Graph-level: failed verification injects retry_feedback for the next loop."""
        from backend.orchestrator.graph import IncidentGraphBuilder
        zt = _zero_trust(tmp_path)
        llm = _llm_with("RESOLVED: false\nREASON: error still present in logs")
        builder = IncidentGraphBuilder(
            _make_config(), llm, AsyncMock(), AsyncMock(),
            CostCircuitBreaker(max_cost_usd=5.0),
            vault=zt["vault"], gateway=zt["gateway"],
            throttle=zt["throttle"], registry=zt["registry"],
        )
        incident = Incident(id="INC-RF", symptom="boom",
                            root_cause="bad port", fix_applied="changed port",
                            retry_count=0)
        state = {"incident": incident, "service_context": "",
                 "tool_results": [], "tool_loop_count": 0}
        result = await builder._verification_node(state)
        assert result["incident"].state == IncidentState.DIAGNOSIS
        assert "retry_feedback" in result
        assert "bad port" in result["retry_feedback"]
        assert "changed port" in result["retry_feedback"]
        assert "error still present" in result["retry_feedback"]

    @pytest.mark.asyncio
    async def test_triage_node_carries_memory_hints_forward(self, tmp_path):
        from backend.orchestrator.graph import IncidentGraphBuilder
        zt = _zero_trust(tmp_path)
        llm = _llm_with("SEVERITY: high\nVERDICT: INVESTIGATE\nSUMMARY: known issue")
        mem = AsyncMock()
        mem.get_relevant = AsyncMock(return_value=[
            MemoryEntry(id="H1", symptom="redis timeout", root_cause="maxmemory",
                        fix="raise maxmemory", vectors=["redis"]),
        ])
        builder = IncidentGraphBuilder(
            _make_config(), llm, AsyncMock(), mem,
            CostCircuitBreaker(max_cost_usd=5.0),
            vault=zt["vault"], gateway=zt["gateway"],
            throttle=zt["throttle"], registry=zt["registry"],
        )
        incident = Incident(id="INC-MH", symptom="redis timeout again")
        state = {"incident": incident, "service_context": "",
                 "tool_results": [], "tool_loop_count": 0}
        result = await builder._triage_node(state)
        hints = result.get("memory_hints")
        assert hints and hints[0]["fix"] == "raise maxmemory"

    @pytest.mark.asyncio
    async def test_triage_queries_memory_with_keywords(self, tmp_path):
        from backend.orchestrator.graph import IncidentGraphBuilder
        zt = _zero_trust(tmp_path)
        llm = _llm_with("SEVERITY: low\nVERDICT: INVESTIGATE\nSUMMARY: s")
        mem = AsyncMock()
        mem.get_relevant = AsyncMock(return_value=[])
        builder = IncidentGraphBuilder(
            _make_config(), llm, AsyncMock(), mem,
            CostCircuitBreaker(max_cost_usd=5.0),
            vault=zt["vault"], gateway=zt["gateway"],
            throttle=zt["throttle"], registry=zt["registry"],
        )
        incident = Incident(id="INC-KW",
                            symptom="ERROR: Connection refused on port 5432")
        state = {"incident": incident, "service_context": "",
                 "tool_results": [], "tool_loop_count": 0}
        await builder._triage_node(state)
        query = mem.get_relevant.call_args[0][0]
        assert "connection" in query
        assert "5432" in query
        assert "error" not in query  # noise word excluded
