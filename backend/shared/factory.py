"""
P1.1 — Composition root.

``build_container(settings)`` is the single place where every Zero-Trust
primitive, the memory store, tool executor, LLM client, circuit breaker,
orchestrator, and log watcher get wired up. Before P1.1 this logic was
duplicated between ``backend/api/app.py::lifespan`` and
``backend/tests/e2e/conftest.py::build_live_stack``. Both now call into
this function.

The factory is intentionally permissive about what it's given:

* If ``settings`` is ``None`` it calls :func:`backend.shared.settings.get_settings`.
* ``llm_override`` lets E2E fixtures inject a ``FakeLLMClient`` without
  having to redo the whole wiring.
* ``override_paths`` is a dict of filesystem path overrides — used by
  tests to point ``audit_log`` / ``memory`` / ``stop_file`` at a tmpdir
  without mutating the real ``Settings``.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from backend.shared.container import ServiceContainer
from backend.shared.settings import Settings, get_settings

logger = logging.getLogger(__name__)


def build_container(
    settings: Optional[Settings] = None,
    *,
    llm_override: Any = None,
) -> ServiceContainer:
    """Build a fully-wired :class:`ServiceContainer`.

    Parameters
    ----------
    settings:
        Optional pre-built settings. If ``None`` we read from the
        environment via :func:`get_settings`.
    llm_override:
        Optional LLM client (e.g. ``FakeLLMClient``) to inject instead
        of the one produced from settings. Used by E2E tests.
    """
    # Imports are local so that ``import backend.shared.factory`` is
    # cheap and doesn't eagerly pull in the Anthropic SDK etc.
    from backend.memory.store import JSONMemoryStore
    from backend.orchestrator.engine import Orchestrator
    from backend.orchestrator.llm_client import create_llm_client
    from backend.shared.agent_throttle import AgentThrottle
    from backend.shared.ai_gateway import AIGateway
    from backend.shared.audit_log import ImmutableAuditLog
    from backend.shared.circuit_breaker import CostCircuitBreaker
    from backend.shared.security import SecurityGuard
    from backend.shared.tool_registry import create_default_registry
    from backend.shared.vault import LocalVault
    from backend.tools.executor import ToolExecutor
    from backend.watcher.log_watcher import LogWatcher

    settings = settings or get_settings()
    config = settings.to_app_config()

    vault = LocalVault()
    gateway = AIGateway()
    throttle = AgentThrottle(max_actions_per_minute=5)
    registry = create_default_registry()
    security = SecurityGuard(config.security)

    # ── P1.2: conditional persistence layer ───────────────────────────
    #
    # When ``settings.database_url`` is set we build a SQLAlchemy engine
    # and use the Postgres-backed memory + audit log + incident
    # repositories. When it's empty (the legacy default), we fall back
    # to the JSON-on-disk memory store and JSONL audit log so the old
    # docker-compose behaviour keeps working.
    database = None
    incident_repo = None
    if settings.database_url:
        from backend.persistence.repositories.audit_repo import PostgresAuditLog
        from backend.persistence.repositories.incident_repo import IncidentRepository
        from backend.persistence.repositories.memory_repo import PostgresMemoryRepo
        from backend.persistence.session import build_database

        database = build_database(settings.database_url)
        memory = PostgresMemoryRepo(database)
        audit_log = PostgresAuditLog(database)
        incident_repo = IncidentRepository(database)
        logger.info("persistence: Postgres/SQLAlchemy mode (%s)", settings.database_url.split("://", 1)[0])
    else:
        memory = JSONMemoryStore(config.memory)
        audit_log = ImmutableAuditLog(config.audit_log_path)
        logger.info("persistence: JSON/file mode (set DATABASE_URL to switch)")

    tools = ToolExecutor(
        security,
        config.security.project_root,
        audit_log=audit_log,
        registry=registry,
        # P1.4: wire the vault so the executor enforces JIT credentials.
        # Every tool call must now present a credential issued by this
        # same vault; forged/replayed credentials are hard-rejected.
        vault=vault,
    )

    if llm_override is not None:
        llm = llm_override
    else:
        llm = create_llm_client(config)

    cb = CostCircuitBreaker(max_cost_usd=config.security.max_cost_per_10min_usd)

    orchestrator = Orchestrator(
        config,
        llm,
        tools,
        memory,
        cb,
        audit_log=audit_log,
        vault=vault,
        gateway=gateway,
        throttle=throttle,
        registry=registry,
        # P1.3: pass incident persistence + timeout knob.
        incident_repo=incident_repo,
        orchestrator_timeout_seconds=settings.orchestrator_timeout_seconds,
    )
    watcher = LogWatcher(config.watcher)

    container = ServiceContainer(
        settings=settings,
        config=config,
        vault=vault,
        gateway=gateway,
        audit_log=audit_log,
        throttle=throttle,
        registry=registry,
        security=security,
        memory=memory,
        tools=tools,
        llm=llm,
        circuit_breaker=cb,
        orchestrator=orchestrator,
        watcher=watcher,
        database=database,
        incident_repo=incident_repo,
    )

    logger.info(
        "ServiceContainer built (mode=%s, provider=%s)",
        config.security.mode.value,
        config.llm_provider.value,
    )
    return container


__all__ = ["build_container"]
