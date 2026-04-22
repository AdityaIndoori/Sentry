"""
P1.1 — ServiceContainer.

Aggregates every long-lived singleton that the API, orchestrator, and
tooling layer need. Replaces the ad-hoc module-level globals previously
scattered across ``backend/api/app.py``.

The container is built exactly once by :func:`backend.shared.factory.build_container`
(the composition root). ``create_app(container)`` in ``backend.api.app``
attaches it to ``FastAPI.state.container`` so every request handler can
pull its dependencies via ``request.app.state.container`` or the
``get_container`` FastAPI dependency.

For the life of P1.1 a second, parallel path is preserved: the module
globals in ``backend.api.app`` are populated during lifespan and read as
a fallback by handlers. This keeps the 500+ unit tests — which
``patch("backend.api.app._orchestrator", ...)`` — green. P1.2+ will
migrate them to container-based fixtures and the globals will be
removed.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ServiceContainer:
    """Holds every singleton wired by the composition root."""

    # Configuration snapshot the container was built from.
    settings: Any = None          # backend.shared.settings.Settings
    config: Any = None            # backend.shared.config.AppConfig (legacy view)

    # Zero-Trust primitives
    vault: Any = None             # LocalVault
    gateway: Any = None           # AIGateway
    audit_log: Any = None         # ImmutableAuditLog
    throttle: Any = None          # AgentThrottle
    registry: Any = None          # TrustedToolRegistry
    security: Any = None          # SecurityGuard

    # Memory + tool executor
    memory: Any = None            # JSONMemoryStore (→ PostgresMemoryRepo in P1.2)
    tools: Any = None             # ToolExecutor

    # LLM + pipeline
    llm: Any = None               # ILLMClient
    circuit_breaker: Any = None   # CostCircuitBreaker
    orchestrator: Any = None      # Orchestrator
    watcher: Any = None           # LogWatcher

    # P1.2: persistence layer (optional; None → JSON fallback)
    database: Any = None          # backend.persistence.session.Database
    incident_repo: Any = None     # backend.persistence.repositories.incident_repo.IncidentRepository

    # P2.1: bearer-token registry. Empty → auth disabled (dev mode).
    auth_tokens: Any = None       # backend.api.auth.TokenRegistry

    # Watcher->orchestrator dispatch task (owned by the container so
    # shutdown can cancel it cleanly).
    watcher_task: Optional[asyncio.Task] = None

    # Serializes concurrent calls to /api/watcher/start and
    # /api/watcher/stop so two concurrent requests can't spawn duplicate
    # event loops or clobber the task handle.
    watcher_ctl_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def shutdown(self) -> None:
        """Stop background tasks and release resources."""
        # 1) Cancel watcher dispatch task (if any)
        if self.watcher_task and not self.watcher_task.done():
            self.watcher_task.cancel()
            try:
                await self.watcher_task
            except (asyncio.CancelledError, Exception):  # pragma: no cover
                pass
            self.watcher_task = None

        # 2) Stop the log watcher
        if self.watcher is not None:
            try:
                await self.watcher.stop()
            except Exception:  # pragma: no cover
                logger.exception("watcher shutdown failed")

        # 3) Dispose the DB engine (if any) last so any in-flight
        #    shutdown writes from 1+2 can still persist.
        if self.database is not None:
            try:
                await self.database.dispose()
            except Exception:  # pragma: no cover
                logger.exception("database dispose failed")


__all__ = ["ServiceContainer"]
