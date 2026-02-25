"""
FastAPI application - API gateway for Sentry dashboard.
Provides REST endpoints for the frontend UI.
"""

import asyncio
import contextvars
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from backend.shared.circuit_breaker import CostCircuitBreaker
from backend.shared.config import load_config, LLMProvider
from backend.shared.models import LogEvent
from backend.shared.security import SecurityGuard
from backend.shared.vault import LocalVault, AgentRole
from backend.shared.ai_gateway import AIGateway
from backend.shared.audit_log import ImmutableAuditLog
from backend.shared.agent_throttle import AgentThrottle
from backend.shared.security import SecurityGuard as _SecurityGuardForSanitize
from backend.shared.tool_registry import TrustedToolRegistry, create_default_registry
from backend.memory.store import JSONMemoryStore
from backend.mcp_tools.executor import MCPToolExecutor
from backend.orchestrator.engine import Orchestrator
from backend.orchestrator.llm_client import create_llm_client
from backend.watcher.log_watcher import LogWatcher

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


# Global references set during lifespan
_orchestrator: Orchestrator = None
_watcher: LogWatcher = None
_config = None
_watcher_task: object = None  # asyncio.Task for the watcher->orchestrator loop


@asynccontextmanager
async def lifespan(app: FastAPI):  # pragma: no cover
    """Application startup and shutdown."""
    global _orchestrator, _watcher, _config

    _config = load_config()
    log_level = getattr(logging, _config.log_level)
    log_format = "%(asctime)s %(levelname)s [%(request_id)s] %(name)s:%(message)s"

    # Install the RequestID filter and formatter on ALL loggers
    rid_filter = RequestIDFilter()
    formatter = logging.Formatter(log_format)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addFilter(rid_filter)

    # If root has no handlers yet, add a console handler
    if not root_logger.handlers:
        console = logging.StreamHandler()
        console.setLevel(log_level)
        root_logger.addHandler(console)

    # Apply our formatter + filter to ALL existing handlers on root
    for handler in root_logger.handlers:
        handler.setFormatter(formatter)
        handler.addFilter(rid_filter)

    # Also install filter + formatter on uvicorn loggers (they don't propagate)
    for uv_logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        uv_log = logging.getLogger(uv_logger_name)
        uv_log.addFilter(rid_filter)
        for handler in uv_log.handlers:
            handler.setFormatter(formatter)
            handler.addFilter(rid_filter)

    # Add timestamped file handler if LOG_FILE_DIR is set
    if _config.log_file_dir:
        os.makedirs(_config.log_file_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = os.path.join(_config.log_file_dir, f"backend_{timestamp}.log")
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(rid_filter)
        # Attach to root logger (catches backend.* loggers)
        logging.getLogger().addHandler(file_handler)
        # Attach to uvicorn loggers (they don't propagate to root by default)
        for uv_logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
            logging.getLogger(uv_logger_name).addHandler(file_handler)
        logger.info(f"Logging to file: {log_file}")

    security = SecurityGuard(_config.security)
    memory = JSONMemoryStore(_config.memory)
    tools = MCPToolExecutor(security, _config.security.project_root)
    llm = create_llm_client(_config)
    cb = CostCircuitBreaker(
        max_cost_usd=_config.security.max_cost_per_10min_usd
    )

    _orchestrator = Orchestrator(_config, llm, tools, memory, cb)
    _watcher = LogWatcher(_config.watcher)

    logger.info(f"Sentry started in {_config.security.mode.value} mode")
    yield
    if _watcher:
        await _watcher.stop()
    logger.info("Sentry shutdown")


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
    allow_headers=["*", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)
app.add_middleware(RequestIDMiddleware)


# --- Pydantic models for request validation ---

class TriggerEventRequest(BaseModel):
    source: str = "manual"
    message: str


class ModeChangeRequest(BaseModel):
    mode: str  # ACTIVE, AUDIT, DISABLED


# --- API Endpoints ---

@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/status")
async def get_status():
    if not _orchestrator:
        raise HTTPException(503, "Orchestrator not initialized")
    status = await _orchestrator.get_status()
    status["watcher_running"] = _watcher._running if _watcher else False
    return status


@app.get("/api/incidents")
async def get_incidents():
    if not _orchestrator:
        raise HTTPException(503, "Not ready")
    active = await _orchestrator.get_active_incidents()
    return {
        "active": [i.to_dict() for i in active],
        "resolved": [i.to_dict() for i in _orchestrator._resolved_incidents[-20:]],
    }


@app.get("/api/incidents/{incident_id}")
async def get_incident_detail(incident_id: str):
    """Get detailed incident info including full activity log."""
    if not _orchestrator:
        raise HTTPException(503, "Not ready")
    # Check active incidents first
    if incident_id in _orchestrator._active_incidents:
        return _orchestrator._active_incidents[incident_id].to_dict()
    # Check resolved incidents
    for inc in _orchestrator._resolved_incidents:
        if inc.id == incident_id:
            return inc.to_dict()
    raise HTTPException(404, f"Incident {incident_id} not found")


@app.post("/api/trigger")
async def trigger_event(req: TriggerEventRequest):
    if not _orchestrator:
        raise HTTPException(503, "Not ready")

    # Sanitize user input before creating the log event
    sanitized_message = req.message
    if _config:
        guard = SecurityGuard(_config.security)
        sanitized_message = guard.sanitize_input(req.message)

    event = LogEvent(
        source_file=req.source,
        line_content=sanitized_message,
        timestamp=datetime.now(timezone.utc),
        matched_pattern="manual",
    )
    incident = await _orchestrator.handle_event(event)
    if incident:
        return {"incident": incident.to_dict()}
    return {"incident": None, "message": "Circuit breaker active or event ignored"}


@app.get("/api/memory")
async def get_memory():
    if not _orchestrator:
        raise HTTPException(503, "Not ready")
    store = _orchestrator._memory
    entries = await store.load()
    return {
        "count": len(entries),
        "entries": [e.to_dict() for e in entries[-20:]],
        "fingerprint": await store.get_fingerprint(),
    }


@app.get("/api/tools")
async def get_tools():
    if not _orchestrator:
        raise HTTPException(503, "Not ready")
    return {"tools": _orchestrator._tools.get_tool_definitions()}


async def _watcher_event_loop():  # pragma: no cover
    """Background task: reads watcher events and feeds them to the orchestrator."""
    logger.info("Watcher event loop started")
    try:
        async for event in _watcher.events():
            logger.info(f"Watcher detected: {event.line_content[:80]}")
            try:
                await _orchestrator.handle_event(event)
            except Exception as e:
                logger.error(f"Orchestrator error processing event: {e}")
    except asyncio.CancelledError:
        logger.info("Watcher event loop cancelled")
    except Exception as e:
        logger.error(f"Watcher event loop error: {e}")
    logger.info("Watcher event loop ended")


@app.post("/api/watcher/start")
async def start_watcher():
    global _watcher_task
    if not _watcher:
        raise HTTPException(503, "Not ready")
    if _watcher._running:
        return {"status": "already_running"}
    await _watcher.start()
    _watcher_task = asyncio.create_task(_watcher_event_loop())
    return {"status": "started"}


@app.post("/api/watcher/stop")
async def stop_watcher():
    global _watcher_task
    if not _watcher:
        raise HTTPException(503, "Not ready")
    await _watcher.stop()
    if _watcher_task and not _watcher_task.done():
        _watcher_task.cancel()
        _watcher_task = None
    return {"status": "stopped"}


@app.get("/api/config")
async def get_config():
    """Return safe configuration values for the dashboard (no API keys)."""
    if not _config:
        raise HTTPException(503, "Not ready")

    # Determine provider and model
    provider = _config.llm_provider
    if provider == LLMProvider.BEDROCK_GATEWAY:
        model = _config.bedrock_gateway.model if hasattr(_config, 'bedrock_gateway') and _config.bedrock_gateway else "unknown"
    else:
        model = _config.anthropic.model if hasattr(_config, 'anthropic') and _config.anthropic else "unknown"

    return {
        "llm_provider": provider.value,
        "model": model,
        "mode": _config.security.mode.value,
        "service_source_path": _config.security.project_root,
        "watch_paths": _config.watcher.watch_paths,
        "poll_interval": _config.watcher.poll_interval_seconds,
        "max_cost_10min": _config.security.max_cost_per_10min_usd,
        "max_retries": _config.security.max_retries,
        "restart_cooldown": _config.security.restart_cooldown_seconds,
        "log_level": _config.log_level,
        "environment": _config.environment,
    }


@app.get("/api/security")
async def get_security_status():
    """Zero Trust security posture dashboard data."""
    import os

    if not _config:
        raise HTTPException(503, "Not ready")

    registry = create_default_registry()

    agent_roles = {}
    for role in AgentRole:
        tools = registry.get_tools_for_role(role)
        agent_roles[role.value] = {
            "tools_allowed": tools,
            "tool_count": len(tools),
        }

    stop_file_exists = os.path.exists(_config.security.stop_file_path)

    return {
        "zero_trust": {
            "vault": "active",
            "ai_gateway": "active",
            "audit_log": "active",
            "agent_throttle": "active",
            "tool_registry": "active",
        },
        "mode": _config.security.mode.value,
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
            {"name": "Cost Circuit Breaker", "status": "OK", "description": "Max $" + str(_config.security.max_cost_per_10min_usd) + "/10min"},
            {"name": "Rate Limiter", "status": "OK", "description": "Restart cooldown: " + str(_config.security.restart_cooldown_seconds) + "s"},
        ],
        "circuit_breaker": _orchestrator._cb.get_status() if _orchestrator else {},
    }
