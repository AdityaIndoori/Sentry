"""
P2.3b-full — OpenTelemetry SDK integration.

This module is the single point where Sentry opts into real OTel
tracing + FastAPI / httpx / asyncpg auto-instrumentation when the
operator has configured an OTLP endpoint. Every hot-path span (agent
phase, tool call, LLM call) is emitted through the
:class:`Telemetry.span` context manager.

Design contract
---------------
* Zero hard deps: when the ``opentelemetry-*`` packages are not
  installed (e.g. the dev machine running pytest without the full
  production requirements), :func:`init_telemetry` returns a no-op
  :class:`Telemetry` that silently swallows every ``span(...)`` call.
  The rest of the codebase can decorate freely.
* Deterministic: the tracer provider is installed exactly once per
  process (guarded by a module-level flag). Re-init is a no-op so
  pytest fixtures and hot reloaders don't clobber state.
* Settings-driven: ``settings.otel_exporter_otlp_endpoint`` toggles the
  exporter. Empty / missing endpoint means "use the no-op provider",
  which still emits spans to any in-process subscriber but performs no
  network I/O.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator
from typing import Any

logger = logging.getLogger(__name__)


# P4.9g — ``ImportError`` fallback for the optional OTel SDK. When the
# operator skips the OTel install (dev machines without the extras),
# each imported symbol is rebound to ``None`` so the rest of the module
# can guard on ``_OTEL_AVAILABLE``. Mypy sees the real types in the
# ``try`` branch, so the fallback assignments are annotated as ``Any``
# with ``type: ignore`` tags to make the narrowing explicit without
# hiding real errors elsewhere.
try:  # pragma: no cover — optional dep
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        ConsoleSpanExporter,
    )

    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
    except ImportError:  # pragma: no cover
        OTLPSpanExporter = None  # type: ignore[assignment,misc]

    _OTEL_AVAILABLE = True
except ImportError:  # pragma: no cover
    trace = None  # type: ignore[assignment]
    Resource: Any = None  # type: ignore[assignment,misc,no-redef]
    TracerProvider: Any = None  # type: ignore[assignment,misc,no-redef]
    BatchSpanProcessor: Any = None  # type: ignore[assignment,misc,no-redef]
    ConsoleSpanExporter: Any = None  # type: ignore[assignment,misc,no-redef]
    OTLPSpanExporter: Any = None  # type: ignore[assignment,misc,no-redef]
    _OTEL_AVAILABLE = False



# ─── FastAPI / httpx / asyncpg instrumentation plumbing ────────────────


def _maybe_instrument_fastapi(app: Any) -> None:  # pragma: no cover
    if not _OTEL_AVAILABLE:
        return
    try:
        from opentelemetry.instrumentation.fastapi import (
            FastAPIInstrumentor,
        )
        FastAPIInstrumentor.instrument_app(app)
        logger.info("OTel: FastAPI instrumented")
    except Exception as exc:
        logger.warning("OTel: FastAPI instrumentation failed: %s", exc)


def _maybe_instrument_httpx() -> None:  # pragma: no cover
    if not _OTEL_AVAILABLE:
        return
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        HTTPXClientInstrumentor().instrument()
    except Exception as exc:
        logger.debug("OTel: httpx instrumentation skipped: %s", exc)


def _maybe_instrument_asyncpg() -> None:  # pragma: no cover
    if not _OTEL_AVAILABLE:
        return
    try:
        from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor
        AsyncPGInstrumentor().instrument()
    except Exception as exc:
        logger.debug("OTel: asyncpg instrumentation skipped: %s", exc)


# ─── Telemetry facade ──────────────────────────────────────────────────


class Telemetry:
    """Thin wrapper around an OTel tracer with a no-op fallback.

    Always safe to call — if OTel isn't installed or ``init_telemetry``
    was never called with a real endpoint, ``span(...)`` returns a
    null context manager.
    """

    def __init__(self, tracer: Any | None = None, service_name: str = "sentry") -> None:
        self._tracer = tracer
        self._service_name = service_name

    @contextlib.contextmanager
    def span(self, name: str, **attrs: Any) -> Iterator[Any]:
        """Open a span named ``name`` with optional string/int/bool attrs."""
        if self._tracer is None:
            # Null span — ``with telemetry.span(...) as s: ...`` still works.
            yield None
            return
        with self._tracer.start_as_current_span(name) as sp:  # pragma: no cover
            try:
                for k, v in attrs.items():
                    with contextlib.suppress(Exception):
                        sp.set_attribute(k, v)
                yield sp
            except Exception as exc:
                try:
                    sp.record_exception(exc)
                    if trace is not None:
                        sp.set_status(trace.Status(trace.StatusCode.ERROR, str(exc)))
                except Exception:
                    pass
                raise

    def is_enabled(self) -> bool:
        return self._tracer is not None


_TELEMETRY: Telemetry = Telemetry()
_INITIALIZED = False


def get_telemetry() -> Telemetry:
    """Return the process-wide :class:`Telemetry` (no-op until init)."""
    return _TELEMETRY


def init_telemetry(
    settings: Any,
    *,
    app: Any = None,
    force_reinit: bool = False,
) -> Telemetry:
    """Install the OTel provider + exporter if the operator opted in.

    Parameters
    ----------
    settings:
        Any object exposing ``otel_exporter_otlp_endpoint`` and
        ``service_name`` (our Settings dataclass satisfies this).
    app:
        Optional FastAPI app — if provided we also install the FastAPI
        auto-instrumentation (trace requests end-to-end).
    force_reinit:
        Tests may pass ``True`` to re-install the provider.

    Returns
    -------
    The process-wide :class:`Telemetry`. Always safe to use.
    """
    global _TELEMETRY, _INITIALIZED
    if _INITIALIZED and not force_reinit:
        if app is not None:
            _maybe_instrument_fastapi(app)
        return _TELEMETRY

    endpoint = getattr(settings, "otel_exporter_otlp_endpoint", None)
    service = getattr(settings, "service_name", "sentry") or "sentry"

    if not _OTEL_AVAILABLE or not endpoint:
        logger.info(
            "Telemetry: OTel disabled (available=%s, endpoint=%s) — using no-op tracer",
            _OTEL_AVAILABLE, endpoint or "<unset>",
        )
        _TELEMETRY = Telemetry(tracer=None, service_name=service)
        _INITIALIZED = True
        if app is not None:
            # FastAPI instrumentation only has effect when OTel is live,
            # but invoking it when off costs nothing.
            _maybe_instrument_fastapi(app)
        return _TELEMETRY

    # Real OTel path.
    try:  # pragma: no cover — exercised only when the deps are installed
        resource = Resource.create({"service.name": service})
        provider = TracerProvider(resource=resource)

        # OTLP first, fall back to console if the exporter isn't importable.
        if OTLPSpanExporter is not None:
            try:
                exporter: Any = OTLPSpanExporter(endpoint=endpoint, insecure=True)
            except Exception as exc:
                logger.warning("OTLP exporter init failed (%s) — using console", exc)
                exporter = ConsoleSpanExporter()
        else:
            exporter = ConsoleSpanExporter()

        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        tracer = trace.get_tracer("sentry.orchestrator")

        _TELEMETRY = Telemetry(tracer=tracer, service_name=service)
        _INITIALIZED = True

        _maybe_instrument_httpx()
        _maybe_instrument_asyncpg()
        if app is not None:
            _maybe_instrument_fastapi(app)

        logger.info("Telemetry: OTel ready (service=%s, endpoint=%s)", service, endpoint)
        return _TELEMETRY
    except Exception as exc:  # pragma: no cover — defensive
        logger.exception("Telemetry: failed to init OTel (%s) — falling back to no-op", exc)
        _TELEMETRY = Telemetry(tracer=None, service_name=service)
        _INITIALIZED = True
        return _TELEMETRY


def reset_for_tests() -> None:  # pragma: no cover
    """Test hook: revert to the no-op tracer so the next init can run."""
    global _TELEMETRY, _INITIALIZED
    _TELEMETRY = Telemetry()
    _INITIALIZED = False


__all__ = [
    "Telemetry",
    "get_telemetry",
    "init_telemetry",
    "reset_for_tests",
]
