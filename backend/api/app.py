"""
FastAPI application — API gateway for Sentry dashboard.

P1.1 refactor
-------------
The legacy module-level globals (``_orchestrator``, ``_watcher``,
``_config``, ``_vault``, ``_gateway``, ``_audit_log``, ``_throttle``,
``_registry``, ``_watcher_task``, ``_watcher_ctl_lock``) are retained as
**backwards-compat shims** so the existing ~500 unit tests that
``patch("backend.api.app._orchestrator", ...)`` keep working unchanged.

The real composition root is now :func:`backend.shared.factory.build_container`
which returns a :class:`backend.shared.container.ServiceContainer`.
``create_app(container=None)`` attaches the container to
``app.state.container`` and every endpoint first tries to pull its
dependencies from there, falling back to the globals only if no
container is attached (i.e. in the legacy unit-test harness).

The module-level ``app`` is still exported so ``from backend.api.app import app``
continues to work — it's created by ``create_app()`` without a
pre-built container; the container is assembled inside ``lifespan()``
and also written back to the globals.

P1.2 will drop the globals once all call-sites have been migrated to
``Depends(get_container)``.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from backend.api.auth import AuthMiddleware, require_scope
from backend.shared.config import LLMProvider
from backend.shared.container import ServiceContainer
from backend.shared.factory import build_container
from backend.shared.models import LogEvent
from backend.shared.security import SecurityGuard
from backend.shared.settings import get_settings
from backend.shared.vault import AgentRole
from backend.shared.tool_registry import create_default_registry

logger = logging.getLogger(__name__)

# ── Request ID tracking via ContextVar ────────────────────────────────────────
_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")


class RequestIDFilter(logging.Filter):
    """Injects the current request ID into every log record."""

    def filter(self, record):
        record.request_id = _request_id_ctx.get("-")
        return True


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Generates a unique request ID, stores it in ContextVar, adds to response header."""

    async def dispatch(self, request: Request, call_next):
        request_id = uuid.uuid4().hex[:12]
        _request_id_ctx.set(request_id)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# ─── Legacy module-level globals (backwards-compat shim) ────────────────────
# These are populated by lifespan() and are the fallback source of
# truth for endpoint handlers when no ServiceContainer has been
# attached to ``app.state.container``. Unit tests continue to
# ``patch("backend.api.app._orchestrator", ...)`` etc. in the usual
# way; the patched value wins over the container because when these
# globals are being patched by tests, the lifespan has not run, so
# ``app.state.container`` is not present.
#
# TODO(P1.2): delete these globals once all tests move to the
# container-based fixtures in ``backend.tests.e2e.conftest``.
_orchestrator = None  # type: ignore[var-annotated]
_watcher = None  # type: ignore[var-annotated]
_config = None  # type: ignore[var-annotated]
_vault = None  # type: ignore[var-annotated]
_gateway = None  # type: ignore[var-annotated]
_audit_log = None  # type: ignore[var-annotated]
_throttle = None  # type: ignore[var-annotated]
_registry = None  # type: ignore[var-annotated]
_watcher_task: Optional[asyncio.Task] = None
_watcher_ctl_lock: asyncio.Lock = asyncio.Lock()


# ─── Helpers to read services from either the container or the globals ─────

def _get_container(request: Request) -> Optional[ServiceContainer]:
    """Return the ServiceContainer attached to this app, if any."""
    try:
        return request.app.state.container  # type: ignore[union-attr]
    except AttributeError:
        return None


def _pick(request: Request, attr: str, global_name: str):
    """
    Pull ``attr`` off the container if one is attached; otherwise fall
    back to the module global ``global_name``. This is the only place
    that knows about the legacy dual path.
    """
    container = _get_container(request)
    if container is not None:
        val = getattr(container, attr, None)
        if val is not None:
            return val
    # Read the module global LIVE so that unittest.mock.patch still works.
    return globals().get(global_name)


# ─── Lifespan ───────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):  # pragma: no cover
    """Application startup and shutdown.

    Builds a ServiceContainer via the factory, attaches it to
    ``app.state.container``, and mirrors the individual services to the
    legacy module globals for backwards compatibility.
    """
    global _orchestrator, _watcher, _config
    global _vault, _gateway, _audit_log, _throttle, _registry

    settings = get_settings()
    container = build_container(settings)
    app.state.container = container

    # Legacy globals (backwards compat — see note above).
    _orchestrator = container.orchestrator
    _watcher = container.watcher
    _config = container.config
    _vault = container.vault
    _gateway = container.gateway
    _audit_log = container.audit_log
    _throttle = container.throttle
    _registry = container.registry

    # Install request-id logging filter.
    log_level = getattr(logging, container.config.log_level, logging.INFO)
    log_format = "%(asctime)s %(levelname)s [%(request_id)s] %(name)s:%(message)s"
    rid_filter = RequestIDFilter()
    formatter = logging.Formatter(log_format)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addFilter(rid_filter)
    if not root_logger.handlers:
        console = logging.StreamHandler()
        console.setLevel(log_level)
        root_logger.addHandler(console)
    for handler in root_logger.handlers:
        handler.setFormatter(formatter)
        handler.addFilter(rid_filter)
    for uv_logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        uv_log = logging.getLogger(uv_logger_name)
        uv_log.addFilter(rid_filter)
        for handler in uv_log.handlers:
            handler.setFormatter(formatter)
            handler.addFilter(rid_filter)

    if container.config.log_file_dir:
        os.makedirs(container.config.log_file_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = os.path.join(container.config.log_file_dir, f"backend_{timestamp}.log")
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(rid_filter)
        logging.getLogger().addHandler(file_handler)
        for uv_logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
            logging.getLogger(uv_logger_name).addHandler(file_handler)
        logger.info(f"Logging to file: {log_file}")

    logger.info(f"Sentry started in {container.config.security.mode.value} mode")
    try:
        yield
    finally:
        await container.shutdown()
        logger.info("Sentry shutdown")


# ─── Pydantic request bodies ────────────────────────────────────────────────


class TriggerEventRequest(BaseModel):
    source: str = "manual"
    message: str


class ModeChangeRequest(BaseModel):
    mode: str  # ACTIVE, AUDIT, DISABLED


# ─── App factory ────────────────────────────────────────────────────────────


def create_app(container: Optional[ServiceContainer] = None) -> FastAPI:
    """Build a FastAPI app, optionally pre-wired to an existing ServiceContainer.

    * When ``container`` is provided (E2E tests, alternate deployments),
      it is attached to ``app.state.container`` immediately and no
      lifespan-driven build occurs. Callers are responsible for
      calling ``container.shutdown()`` when done.
    * When ``container`` is ``None`` (the default production path), the
      lifespan context manager builds one from :func:`get_settings`.
    """
    if container is not None:
        # Alternate path: caller supplies the container. We skip the
        # lifespan so we don't try to re-build one.
        app = FastAPI(
            title="Sentry",
            description="Self-Healing Server Monitor",
            version="1.0.0",
        )
        app.state.container = container
    else:
        app = FastAPI(
            title="Sentry",
            description="Self-Healing Server Monitor",
            version="1.0.0",
            lifespan=lifespan,
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*", "X-Request-ID", "Authorization"],
        expose_headers=["X-Request-ID"],
    )
    # Order matters: middleware is applied LIFO, so the last one added
    # is the first to run on a request. We want (outermost → innermost):
    # RequestIDMiddleware → AuthMiddleware → CORS → route handler.
    # So we add CORS, then Auth, then RequestID.
    app.add_middleware(AuthMiddleware)
    app.add_middleware(RequestIDMiddleware)

    _register_routes(app)
    return app


# ─── Route registration ─────────────────────────────────────────────────────


def _register_routes(app: FastAPI) -> None:
    """Register every API route on ``app``.

    Handlers use :func:`_pick` to read services from either the attached
    container or the legacy module globals — see the P1.1 note at the
    top of this file.
    """

    @app.get("/api/health")
    async def health():
        """Liveness probe — the process is alive enough to answer.

        Intentionally shallow: no dep checks, no auth, no DB query.
        Suitable for Kubernetes ``livenessProbe`` / docker ``HEALTHCHECK``
        and stays open even when the auth token registry is non-empty
        (see :class:`backend.api.auth.AuthMiddleware`).
        """
        return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

    @app.get("/api/ready")
    async def ready(request: Request):
        """Readiness probe — the backend is ready to serve real traffic.

        Checks each dependency that a "running" Sentry deployment needs:

        * **llm_reachable** — an ``ILLMClient`` instance is wired on the
          container. In tests this is the scripted ``FakeLLMClient``; in
          production it's the Anthropic / Bedrock client.
        * **db_reachable** — only enforced when Postgres is configured
          (``settings.database_url`` non-empty). Issues a short-timeout
          ``SELECT 1``. When Postgres is not in use this returns True
          (the JSON store is always "reachable").
        * **disk_writable** — the audit-log directory accepts a tmp
          file create-and-delete round trip.

        Returns ``200`` with ``{"ready": true, ...}`` when every check
        passes, ``503`` with the same shape + ``"ready": false``
        otherwise. Kubernetes ``readinessProbe`` and load balancers
        should consult this endpoint; liveness stays on ``/api/health``.
        """
        import asyncio as _asyncio
        import os as _os
        import tempfile as _tempfile

        container = _get_container(request)
        cfg = _pick(request, "config", "_config")

        # llm_reachable: truthy ILLMClient on the container (dev/tests
        # use the FakeLLMClient which is always truthy; prod uses
        # Anthropic client).
        llm = container.llm if container is not None else None
        llm_reachable = llm is not None

        # db_reachable: SELECT 1 with a 2-second cap. Skipped when
        # Postgres is not configured (JSON store mode).
        db_reachable = True
        db_error: Optional[str] = None
        settings = container.settings if container is not None else None
        database_url = getattr(settings, "database_url", None) if settings else None
        if database_url and container is not None and container.database is not None:
            try:
                from sqlalchemy import text as _sql_text

                async with container.database.sessionmaker() as session:
                    await _asyncio.wait_for(
                        session.execute(_sql_text("SELECT 1")),
                        timeout=2.0,
                    )
            except Exception as exc:  # pragma: no cover — infra failure
                db_reachable = False
                db_error = str(exc).splitlines()[0][:200]

        # disk_writable: create + remove a tmp file inside the audit
        # log directory (the one location on the hot path that MUST
        # accept writes).
        disk_writable = True
        disk_error: Optional[str] = None
        if cfg is not None:
            probe_dir = _os.path.dirname(cfg.audit_log_path) or "."
            try:
                _os.makedirs(probe_dir, exist_ok=True)
                with _tempfile.NamedTemporaryFile(
                    dir=probe_dir, prefix=".ready_probe_", delete=True,
                ):
                    pass
            except Exception as exc:  # pragma: no cover — infra failure
                disk_writable = False
                disk_error = str(exc).splitlines()[0][:200]

        ready_flag = llm_reachable and db_reachable and disk_writable
        payload = {
            "ready": ready_flag,
            "llm_reachable": llm_reachable,
            "db_reachable": db_reachable,
            "disk_writable": disk_writable,
        }
        if db_error:
            payload["db_error"] = db_error
        if disk_error:
            payload["disk_error"] = disk_error

        if not ready_flag:
            return JSONResponse(status_code=503, content=payload)
        return payload

    @app.get(
        "/api/status",
        dependencies=[Depends(require_scope("incidents:read"))],
    )
    async def get_status(request: Request):
        orch = _pick(request, "orchestrator", "_orchestrator")
        watcher = _pick(request, "watcher", "_watcher")
        if not orch:
            raise HTTPException(503, "Orchestrator not initialized")
        status = await orch.get_status()
        status["watcher_running"] = watcher._running if watcher else False
        return status

    @app.get(
        "/api/incidents",
        dependencies=[Depends(require_scope("incidents:read"))],
    )
    async def get_incidents(request: Request):
        orch = _pick(request, "orchestrator", "_orchestrator")
        if not orch:
            raise HTTPException(503, "Not ready")
        active = await orch.get_active_incidents()
        resolved_list = list(orch._resolved_incidents)[-20:]
        return {
            "active": [i.to_dict() for i in active],
            "resolved": [i.to_dict() for i in resolved_list],
        }

    @app.get(
        "/api/incidents/{incident_id}",
        dependencies=[Depends(require_scope("incidents:read"))],
    )
    async def get_incident_detail(incident_id: str, request: Request):
        orch = _pick(request, "orchestrator", "_orchestrator")
        if not orch:
            raise HTTPException(503, "Not ready")
        if incident_id in orch._active_incidents:
            return orch._active_incidents[incident_id].to_dict()
        for inc in orch._resolved_incidents:
            if inc.id == incident_id:
                return inc.to_dict()
        raise HTTPException(404, f"Incident {incident_id} not found")

    @app.post(
        "/api/trigger",
        dependencies=[Depends(require_scope("incidents:trigger"))],
    )
    async def trigger_event(req: TriggerEventRequest, request: Request):
        orch = _pick(request, "orchestrator", "_orchestrator")
        cfg = _pick(request, "config", "_config")
        if not orch:
            raise HTTPException(503, "Not ready")

        sanitized_message = req.message
        if cfg:
            guard = SecurityGuard(cfg.security)
            sanitized_message = guard.sanitize_input(req.message)

        event = LogEvent(
            source_file=req.source,
            line_content=sanitized_message,
            timestamp=datetime.now(timezone.utc),
            matched_pattern="manual",
        )
        incident = await orch.handle_event(event)
        if incident:
            return {"incident": incident.to_dict()}
        return {"incident": None, "message": "Circuit breaker active or event ignored"}

    @app.get(
        "/api/memory",
        dependencies=[Depends(require_scope("incidents:read"))],
    )
    async def get_memory(request: Request):
        orch = _pick(request, "orchestrator", "_orchestrator")
        if not orch:
            raise HTTPException(503, "Not ready")
        store = orch._memory
        entries = await store.load()
        return {
            "count": len(entries),
            "entries": [e.to_dict() for e in entries[-20:]],
            "fingerprint": await store.get_fingerprint(),
        }

    @app.get(
        "/api/tools",
        dependencies=[Depends(require_scope("incidents:read"))],
    )
    async def get_tools(request: Request):
        orch = _pick(request, "orchestrator", "_orchestrator")
        if not orch:
            raise HTTPException(503, "Not ready")
        return {"tools": orch._tools.get_tool_definitions()}

    @app.post(
        "/api/watcher/start",
        dependencies=[Depends(require_scope("watcher:control"))],
    )
    async def start_watcher(request: Request):
        global _watcher_task
        watcher = _pick(request, "watcher", "_watcher")
        if not watcher:
            raise HTTPException(503, "Not ready")
        container = _get_container(request)
        lock = container.watcher_ctl_lock if container is not None else _watcher_ctl_lock
        async with lock:
            if watcher._running:
                return {"status": "already_running"}
            await watcher.start()
            orch = _pick(request, "orchestrator", "_orchestrator")
            existing_task = (
                container.watcher_task if container is not None else _watcher_task
            )
            if existing_task and not existing_task.done():
                existing_task.cancel()
            task = asyncio.create_task(
                _watcher_event_loop(watcher, orch),
                name="sentry-watcher-dispatch",
            )
            if container is not None:
                container.watcher_task = task
            else:
                _watcher_task = task
            return {"status": "started"}

    @app.post(
        "/api/watcher/stop",
        dependencies=[Depends(require_scope("watcher:control"))],
    )
    async def stop_watcher(request: Request):
        global _watcher_task
        watcher = _pick(request, "watcher", "_watcher")
        if not watcher:
            raise HTTPException(503, "Not ready")
        container = _get_container(request)
        lock = container.watcher_ctl_lock if container is not None else _watcher_ctl_lock
        async with lock:
            await watcher.stop()
            existing_task = (
                container.watcher_task if container is not None else _watcher_task
            )
            if existing_task and not existing_task.done():
                existing_task.cancel()
            if container is not None:
                container.watcher_task = None
            else:
                _watcher_task = None
            return {"status": "stopped"}

    @app.get(
        "/api/config",
        dependencies=[Depends(require_scope("incidents:read"))],
    )
    async def get_config(request: Request):
        cfg = _pick(request, "config", "_config")
        if not cfg:
            raise HTTPException(503, "Not ready")

        provider = cfg.llm_provider
        if provider == LLMProvider.BEDROCK_GATEWAY:
            model = (
                cfg.bedrock_gateway.model
                if hasattr(cfg, "bedrock_gateway") and cfg.bedrock_gateway
                else "unknown"
            )
        else:
            model = (
                cfg.anthropic.model
                if hasattr(cfg, "anthropic") and cfg.anthropic
                else "unknown"
            )

        return {
            "llm_provider": provider.value,
            "model": model,
            "mode": cfg.security.mode.value,
            "service_source_path": cfg.security.project_root,
            "watch_paths": cfg.watcher.watch_paths,
            "poll_interval": cfg.watcher.poll_interval_seconds,
            "max_cost_10min": cfg.security.max_cost_per_10min_usd,
            "max_retries": cfg.security.max_retries,
            "restart_cooldown": cfg.security.restart_cooldown_seconds,
            "log_level": cfg.log_level,
            "environment": cfg.environment,
        }

    @app.get(
        "/api/security",
        dependencies=[Depends(require_scope("incidents:read"))],
    )
    async def get_security_status(request: Request):
        cfg = _pick(request, "config", "_config")
        if not cfg:
            raise HTTPException(503, "Not ready")

        orch = _pick(request, "orchestrator", "_orchestrator")
        vault = _pick(request, "vault", "_vault")
        gateway = _pick(request, "gateway", "_gateway")
        audit_log = _pick(request, "audit_log", "_audit_log")
        throttle = _pick(request, "throttle", "_throttle")
        registry = _pick(request, "registry", "_registry") or create_default_registry()

        agent_roles = {}
        for role in AgentRole:
            tools = registry.get_tools_for_role(role)
            agent_roles[role.value] = {
                "tools_allowed": tools,
                "tool_count": len(tools),
            }

        stop_file_exists = os.path.exists(cfg.security.stop_file_path)

        return {
            "zero_trust": {
                "vault": "active" if vault and not vault.is_killed else "inactive",
                "ai_gateway": "active" if gateway else "inactive",
                "audit_log": "active" if audit_log else "inactive",
                "agent_throttle": "active" if throttle else "inactive",
                "tool_registry": "active" if registry else "inactive",
            },
            "mode": cfg.security.mode.value,
            "stop_file_active": stop_file_exists,
            "agent_roles": agent_roles,
            "security_layers": [
                {"name": "NHI Vault", "status": "OK", "description": "Non-Human Identity credential management"},
                {"name": "AI Gateway", "status": "OK", "description": "Prompt injection and PII leak detection"},
                {"name": "Immutable Audit Log", "status": "OK", "description": "Hash-chained tamper-evident logging"},
                {"name": "Agent Throttle", "status": "OK", "description": "Per-agent action rate limiting"},
                {"name": "Tool Registry", "status": "OK", "description": "Role-based tool access control"},
                {"name": "Path Validation", "status": "OK", "description": "No directory traversal allowed"},
                {"name": "Command Whitelist", "status": "OK", "description": "Only approved commands executable"},
                {"name": "Input Sanitization", "status": "OK", "description": "Shell injection prevention"},
                {"name": "Cost Circuit Breaker", "status": "OK", "description": "Max $" + str(cfg.security.max_cost_per_10min_usd) + "/10min"},
                {"name": "Rate Limiter", "status": "OK", "description": "Restart cooldown: " + str(cfg.security.restart_cooldown_seconds) + "s"},
            ],
            "circuit_breaker": orch._cb.get_status() if orch else {},
        }


# ─── Watcher event dispatch ─────────────────────────────────────────────────


async def _watcher_event_loop(watcher=None, orchestrator=None):  # pragma: no cover
    """Background task: reads watcher events and feeds them to the orchestrator.

    Defaults to the module globals when arguments are omitted, so existing
    tests that patch ``_watcher`` / ``_orchestrator`` keep working.
    """
    w = watcher if watcher is not None else _watcher
    orch = orchestrator if orchestrator is not None else _orchestrator
    logger.info("Watcher event loop started")
    try:
        async for event in w.events():
            logger.info(f"Watcher detected: {event.line_content[:80]}")
            try:
                await orch.handle_event(event)
            except Exception as e:
                logger.error(f"Orchestrator error processing event: {e}")
    except asyncio.CancelledError:
        logger.info("Watcher event loop cancelled")
    except Exception as e:
        logger.error(f"Watcher event loop error: {e}")
    logger.info("Watcher event loop ended")


# ─── Module-level app instance (import-compatibility) ───────────────────────
# ``from backend.api.app import app`` must continue to work. This instance
# uses the standard lifespan path.
app = create_app()
