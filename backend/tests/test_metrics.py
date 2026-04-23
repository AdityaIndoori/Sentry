"""
Unit tests for :mod:`backend.shared.metrics`.

Two scenarios are locked in:

1. ``prometheus_client`` **unavailable** (dev machines without the dep):
   every ``inc_*`` helper is a safe no-op, ``is_available() is False``,
   and ``render_metrics()`` raises ``RuntimeError``.
2. ``prometheus_client`` **available** (production / CI with the full
   requirements installed): counters live in a private
   ``CollectorRegistry``, the helpers increment them, and
   ``render_metrics()`` returns a proper Prometheus text-exposition
   response.

The ``prometheus_client`` branch is guarded by ``pytest.importorskip``
so the test file passes either way — which matches the hybrid dev
environment described at the top of ``backend/shared/metrics.py``.
"""

from __future__ import annotations

import importlib

import pytest

metrics = pytest.importorskip("backend.shared.metrics")  # always importable


def test_helpers_never_raise_when_called_with_sane_args():
    # Whether or not the library is available, these must be safe.
    metrics.inc_incident("resolved")
    metrics.inc_incident("escalated")
    metrics.inc_tool_call("read_file", True)
    metrics.inc_tool_call("apply_patch", False)
    metrics.inc_llm_call()
    metrics.observe_llm_cost(0.123)
    metrics.observe_llm_cost(0.0)    # zero is a no-op
    metrics.observe_llm_cost(-1.0)   # negatives are ignored
    metrics.inc_watcher_event()
    metrics.inc_circuit_breaker_trip()


@pytest.mark.skipif(
    not metrics.is_available(),
    reason="prometheus_client not installed on this machine; only the "
           "no-op branch is exercised",
)
def test_render_metrics_returns_prometheus_text():
    body, content_type = metrics.render_metrics()
    assert isinstance(body, (bytes, bytearray))
    assert b"sentry_incidents_total" in body
    # Prometheus standard content-type (either 0.0.4 or openmetrics; both
    # start with text/plain).
    assert content_type.startswith("text/plain")


@pytest.mark.skipif(
    not metrics.is_available(),
    reason="prometheus_client not installed",
)
def test_counters_increment_is_visible_in_render_output():
    # Grab the counter's current value, bump it, and verify the exposition
    # reflects the bump. We read the internal ``_value.get()`` rather than
    # comparing string output because parsing the exposition format is
    # fragile across prometheus_client versions.
    before = metrics._INCIDENTS.labels(state="test_metric_probe")._value.get()
    metrics.inc_incident("test_metric_probe")
    after = metrics._INCIDENTS.labels(state="test_metric_probe")._value.get()
    assert after == before + 1


def test_render_metrics_raises_when_unavailable(monkeypatch):
    """Simulate the dev-machine branch (no prometheus_client) by forcing
    ``_AVAILABLE = False`` and asserting the correct error is raised."""
    monkeypatch.setattr(metrics, "_AVAILABLE", False)
    with pytest.raises(RuntimeError) as excinfo:
        metrics.render_metrics()
    assert "prometheus_client" in str(excinfo.value).lower()


def test_is_available_matches_import_state():
    """``is_available()`` returns whether ``prometheus_client`` is importable.

    We sanity-check by trying to import it manually and comparing.
    """
    try:
        importlib.import_module("prometheus_client")
        expected = True
    except ImportError:
        expected = False
    assert metrics.is_available() is expected
