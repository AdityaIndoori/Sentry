"""
P2.3b-full — structlog JSON logging with optional trace-id correlation.

This module is called exactly once at process start (from
``backend.api.app.create_app`` lifespan). When ``structlog>=24`` is
installed it installs a JSON-renderer processor chain that interoperates
with the OTel tracer: every log record carries ``trace_id`` / ``span_id``
fields pulled from the current OTel context. When ``structlog`` is not
installed we fall back to stdlib logging.basicConfig with an equivalent
JSON-ish format so the /api/* handlers keep logging.

Design contract
---------------
* Zero hard deps — tests that don't install structlog still see
  configured logging.
* Idempotent: callable many times; second+ calls are no-ops.
* Output always writes to stdout so containers / k8s pick it up via
  the usual logdriver.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

_CONFIGURED = False


try:  # pragma: no cover — optional dep
    import structlog  # type: ignore

    _HAS_STRUCTLOG = True
except ImportError:  # pragma: no cover
    structlog = None  # type: ignore[assignment]
    _HAS_STRUCTLOG = False


try:  # pragma: no cover — optional dep
    from opentelemetry import trace as _otel_trace  # type: ignore

    _HAS_OTEL = True
except ImportError:  # pragma: no cover
    _otel_trace = None  # type: ignore[assignment]
    _HAS_OTEL = False


def _current_trace_ids() -> tuple[str, str]:  # pragma: no cover
    """Return (trace_id_hex, span_id_hex) for the current OTel span, or ("",""). """
    if not _HAS_OTEL:
        return "", ""
    try:
        span = _otel_trace.get_current_span()
        ctx = span.get_span_context()
        if not ctx.is_valid:
            return "", ""
        return f"{ctx.trace_id:032x}", f"{ctx.span_id:016x}"
    except Exception:
        return "", ""


def _add_trace_ids(_logger: Any, _method_name: str, event_dict: dict) -> dict:  # pragma: no cover
    tid, sid = _current_trace_ids()
    if tid:
        event_dict["trace_id"] = tid
    if sid:
        event_dict["span_id"] = sid
    return event_dict


class _JSONFormatter(logging.Formatter):
    """Minimal JSON log line formatter for the structlog-unavailable path."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        tid, sid = _current_trace_ids()
        if tid:
            payload["trace_id"] = tid
        if sid:
            payload["span_id"] = sid
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(*, level: str = "INFO") -> None:
    """Install the global logging config. Idempotent."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    lvl = getattr(logging, level.upper(), logging.INFO)

    if _HAS_STRUCTLOG:  # pragma: no cover
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                _add_trace_ids,
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(lvl),
            logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
            cache_logger_on_first_use=True,
        )
        # Also route stdlib logging through structlog so FastAPI /
        # uvicorn messages land in the same JSON stream.
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JSONFormatter())
        root = logging.getLogger()
        root.handlers.clear()
        root.addHandler(handler)
        root.setLevel(lvl)
    else:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JSONFormatter())
        root = logging.getLogger()
        root.handlers.clear()
        root.addHandler(handler)
        root.setLevel(lvl)

    _CONFIGURED = True
    logging.getLogger(__name__).info(
        "logging: configured (structlog=%s, otel=%s, level=%s)",
        _HAS_STRUCTLOG, _HAS_OTEL, level,
    )


def reset_for_tests() -> None:  # pragma: no cover
    """Test hook: re-allow configure_logging() to run again."""
    global _CONFIGURED
    _CONFIGURED = False


__all__ = ["configure_logging", "reset_for_tests"]
