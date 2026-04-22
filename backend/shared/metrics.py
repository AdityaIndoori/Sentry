"""
P2.3b — Prometheus metrics (optional OSS observability).

Thin wrapper around ``prometheus_client`` that lets the rest of the
codebase call ``increment_incident("resolved")`` / ``observe_llm_cost(0.04)``
without taking a hard dependency on the library. When
``prometheus_client`` is installed the counters are real; when it isn't
(e.g. the dev machine running pytest without the full production
requirements) every helper becomes a no-op and the ``/metrics``
endpoint returns ``503 Service Unavailable``.

This design lets P2.3b ship the metric taxonomy + hot-path instrumentation
today without forcing every contributor to install the full OTel / Prometheus
toolchain. Production deployments (docker-compose / K8s) install
``prometheus_client>=0.20`` from ``backend/requirements.txt``.

Public API
----------
* :func:`is_available` — True if ``prometheus_client`` is importable.
* :func:`inc_incident(state: str)` / :func:`inc_tool_call(tool: str, success: bool)`
  / :func:`inc_watcher_event()` / :func:`inc_circuit_breaker_trip()` /
  :func:`inc_llm_call()` — bump a counter; no-ops if unavailable.
* :func:`observe_llm_cost(usd: float)` — record an LLM cost sample.
* :func:`render_metrics() -> tuple[bytes, str]` — Prometheus text
  exposition format + content-type header. Raises ``RuntimeError`` if
  the library isn't available; the ``/metrics`` FastAPI route catches
  that and returns 503.

The metric names follow the OBS-01..03 contract in ``ops/E2E_TEST_CATALOG.md``:

* ``sentry_incidents_total{state=…}``
* ``sentry_tool_calls_total{tool=…,success=…}``
* ``sentry_llm_calls_total``
* ``sentry_llm_cost_usd_total``
* ``sentry_watcher_events_total``
* ``sentry_circuit_breaker_trips_total``
"""

from __future__ import annotations

import logging
from typing import Tuple

logger = logging.getLogger(__name__)


try:  # pragma: no cover — tested via availability gate
    from prometheus_client import (  # type: ignore[import-not-found]
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        generate_latest,
    )
    _AVAILABLE = True
except ImportError:  # pragma: no cover — dev machines without the dep
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
    CollectorRegistry = None  # type: ignore[assignment,misc]
    Counter = None  # type: ignore[assignment,misc]
    generate_latest = None  # type: ignore[assignment]
    _AVAILABLE = False


def is_available() -> bool:
    """Whether the Prometheus toolchain is importable."""
    return _AVAILABLE


# ────────────────────────────────────────────────────────────────────
# Registry + counter objects — only populated when the library is on
# the PYTHONPATH. Using an explicit registry (rather than the default
# one) makes testing easier and isolates Sentry from any other
# ``prometheus_client`` users in the same process.
# ────────────────────────────────────────────────────────────────────


if _AVAILABLE:
    REGISTRY = CollectorRegistry()

    _INCIDENTS = Counter(
        "sentry_incidents_total",
        "Total incidents grouped by terminal state.",
        labelnames=("state",),
        registry=REGISTRY,
    )
    _TOOL_CALLS = Counter(
        "sentry_tool_calls_total",
        "Total tool executions grouped by tool and outcome.",
        labelnames=("tool", "success"),
        registry=REGISTRY,
    )
    _LLM_CALLS = Counter(
        "sentry_llm_calls_total",
        "Total LLM calls dispatched by the orchestrator.",
        registry=REGISTRY,
    )
    _LLM_COST = Counter(
        "sentry_llm_cost_usd_total",
        "Cumulative LLM cost in USD (from the cost circuit breaker).",
        registry=REGISTRY,
    )
    _WATCHER_EVENTS = Counter(
        "sentry_watcher_events_total",
        "Log lines that the watcher turned into orchestrator events.",
        registry=REGISTRY,
    )
    _CB_TRIPS = Counter(
        "sentry_circuit_breaker_trips_total",
        "Number of times the cost circuit breaker has tripped.",
        registry=REGISTRY,
    )
else:
    REGISTRY = None  # type: ignore[assignment]
    _INCIDENTS = _TOOL_CALLS = _LLM_CALLS = None  # type: ignore[assignment]
    _LLM_COST = _WATCHER_EVENTS = _CB_TRIPS = None  # type: ignore[assignment]


# ────────────────────────────────────────────────────────────────────
# Helper API — always safe to call.
# ────────────────────────────────────────────────────────────────────


def inc_incident(state: str) -> None:
    """Record an incident reaching a terminal ``state``.

    Called from :class:`backend.orchestrator.engine.Orchestrator.handle_event`
    in the ``finally`` block so every lifecycle outcome — RESOLVED / IDLE
    / ESCALATED — increments the right label.
    """
    if not _AVAILABLE:
        return
    try:
        _INCIDENTS.labels(state=str(state)).inc()
    except Exception:  # pragma: no cover — never block the hot path
        logger.exception("metrics: inc_incident(%s) failed", state)


def inc_tool_call(tool: str, success: bool) -> None:
    """Record a tool execution with its ``tool`` name and boolean ``success``."""
    if not _AVAILABLE:
        return
    try:
        _TOOL_CALLS.labels(tool=str(tool), success=("true" if success else "false")).inc()
    except Exception:  # pragma: no cover
        logger.exception("metrics: inc_tool_call(%s) failed", tool)


def inc_llm_call() -> None:
    if not _AVAILABLE:
        return
    try:
        _LLM_CALLS.inc()
    except Exception:  # pragma: no cover
        logger.exception("metrics: inc_llm_call failed")


def observe_llm_cost(usd: float) -> None:
    if not _AVAILABLE:
        return
    try:
        if usd and usd > 0:
            _LLM_COST.inc(float(usd))
    except Exception:  # pragma: no cover
        logger.exception("metrics: observe_llm_cost failed")


def inc_watcher_event() -> None:
    if not _AVAILABLE:
        return
    try:
        _WATCHER_EVENTS.inc()
    except Exception:  # pragma: no cover
        logger.exception("metrics: inc_watcher_event failed")


def inc_circuit_breaker_trip() -> None:
    if not _AVAILABLE:
        return
    try:
        _CB_TRIPS.inc()
    except Exception:  # pragma: no cover
        logger.exception("metrics: inc_circuit_breaker_trip failed")


def render_metrics() -> Tuple[bytes, str]:
    """Return ``(body, content_type)`` for the ``/metrics`` endpoint.

    Raises
    ------
    RuntimeError
        If ``prometheus_client`` is not installed.
    """
    if not _AVAILABLE:
        raise RuntimeError(
            "prometheus_client is not installed; pip install prometheus-client "
            "or remove the /metrics endpoint from your reverse proxy."
        )
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


__all__ = [
    "is_available",
    "inc_incident",
    "inc_tool_call",
    "inc_llm_call",
    "observe_llm_cost",
    "inc_watcher_event",
    "inc_circuit_breaker_trip",
    "render_metrics",
]
