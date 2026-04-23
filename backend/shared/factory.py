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
from typing import Any

from backend.shared.container import ServiceContainer
from backend.shared.settings import Settings, get_settings

logger = logging.getLogger(__name__)


def build_container(
    settings: Settings | None = None,
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
    from backend.api.auth import TokenRegistry, seed_tokens_from_settings
    from backend.orchestrator.engine import Orchestrator
    from backend.orchestrator.llm_client import create_llm_client
    from backend.shared.agent_throttle import AgentThrottle
    from backend.shared.ai_gateway import AIGateway
    from backend.shared.audit_log import ImmutableAuditLog
    from backend.shared.circuit_breaker import CostCircuitBreaker
    from backend.shared.secrets import build_secrets_provider
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

    # ── P1.2 / P3.4b: unified SQLAlchemy persistence ──────────────────
    #
    # Memory is *always* backed by :class:`PostgresMemoryRepo` — the
    # legacy :class:`JSONMemoryStore` was deleted in P3.4b. When
    # ``settings.database_url`` is unset we synthesize an async-SQLite
    # URL next to the configured memory file path so single-process
    # dev + tests work without a running database. In production the
    # operator sets ``DATABASE_URL`` to a real Postgres DSN.
    #
    # Audit log remains dual-mode: the hash-chained JSONL
    # :class:`ImmutableAuditLog` stays the default when no explicit DB
    # URL is set (it writes to disk with no DB round-trip). Setting
    # ``DATABASE_URL`` upgrades it to :class:`PostgresAuditLog`.
    from backend.persistence.repositories.incident_repo import IncidentRepository
    from backend.persistence.repositories.memory_repo import PostgresMemoryRepo
    from backend.persistence.repositories.token_repo import TokenRepository
    from backend.persistence.session import build_database

    database_url = settings.database_url
    synthesized_sqlite = False
    if not database_url:
        # Derive a sqlite file next to the memory path so existing
        # volume mounts (``/app/data``) pick it up automatically.
        import os as _os

        data_dir = _os.path.dirname(config.memory.file_path) or "."
        _os.makedirs(data_dir, exist_ok=True)
        database_url = f"sqlite+aiosqlite:///{_os.path.join(data_dir, 'sentry.db')}"
        synthesized_sqlite = True

    database = build_database(database_url)
    memory = PostgresMemoryRepo(database)
    incident_repo = IncidentRepository(database)
    # P4.2: persistent store for API bearer tokens. Always created —
    # an empty table is indistinguishable from "no persisted tokens"
    # and the env-seeded admin token path is preserved.
    token_repo = TokenRepository(database)

    if settings.database_url:
        from backend.persistence.repositories.audit_repo import PostgresAuditLog
        audit_log = PostgresAuditLog(database)
        logger.info(
            "persistence: SQLAlchemy mode (%s)",
            settings.database_url.split("://", 1)[0],
        )
    else:
        audit_log = ImmutableAuditLog(config.audit_log_path)
        logger.info(
            "persistence: sqlite+file-audit mode (memory=%s, audit=jsonl)",
            database_url,
        )

    # Bootstrap memory tables on first boot for sqlite/dev; Alembic owns
    # schema evolution in production Postgres. Run the async bootstrap
    # in a worker thread with its own event loop so we don't interfere
    # with any pytest-asyncio / lifespan loop already wired into the
    # calling thread.
    if synthesized_sqlite:
        import asyncio as _asyncio
        import threading as _threading

        _err_box: dict[str, BaseException] = {}

        async def _bootstrap_and_dispose() -> None:
            # Run create_all then dispose the engine. Disposing drops the
            # connection pool so subsequent ``sessionmaker()`` calls made
            # from a different event loop (the test/app loop) don't
            # inherit connections bound to this bootstrap loop.
            await database.create_all()
            await database.engine.dispose()

        def _bootstrap_thread() -> None:
            try:
                _asyncio.run(_bootstrap_and_dispose())
            except BaseException as exc:  # pragma: no cover
                _err_box["err"] = exc

        t = _threading.Thread(target=_bootstrap_thread, name="sentry-db-bootstrap", daemon=True)
        t.start()
        t.join()
        if "err" in _err_box:  # pragma: no cover
            raise _err_box["err"]

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

    # ── P2.4: in-process SSE broadcaster ────────────────────────────────
    #
    # One per container. The orchestrator publishes incident state
    # transitions and the /api/stream/incidents route fans them out to
    # every connected dashboard. Shutdown via ``ServiceContainer.shutdown``
    # drains subscribers with a ``None`` sentinel.
    from backend.api.broadcaster import IncidentBroadcaster
    broadcaster = IncidentBroadcaster()

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
        # P2.4: live SSE fan-out.
        broadcaster=broadcaster,
    )
    watcher = LogWatcher(config.watcher)

    # ── P2.2: OSS secrets provider ──────────────────────────────────────
    #
    # Pluggable backend: ``env`` (default) / ``file`` / ``sops`` / ``vault``.
    # When the operator picks a non-env backend, we also opportunistically
    # lift the ``api_auth_token`` out of it so P2.1 auth gating switches on
    # without also requiring the raw token to appear in the env var. This
    # is the primary integration point for P2.2 — the rest of the codebase
    # can keep reading ``settings.api_auth_token`` unmodified.
    secrets_provider = build_secrets_provider(settings)

    effective_settings = settings
    if (not settings.api_auth_token) and secrets_provider is not None:
        loaded = secrets_provider.get("api_auth_token")
        if loaded:
            # Settings is frozen; create a copy with the hydrated token.
            from dataclasses import replace

            effective_settings = replace(settings, api_auth_token=loaded)
            logger.info(
                "Auth: hydrated api_auth_token from secrets backend "
                "(provider=%s)", secrets_provider.__class__.__name__,
            )

    # ── P2.1 + P4.2: bearer-token registry + persistent backing ─────────
    #
    # Empty registry → auth disabled ("dev mode"). Tests that want to
    # exercise auth flows populate this in their fixtures.
    # ``API_AUTH_TOKEN`` (env or secrets backend) seeds a default admin.
    #
    # P4.2: after env seeding we hydrate the registry from the
    # ``api_tokens`` DB table so operator-minted tokens survive restarts.
    # Hydration is idempotent and runs in the same worker-thread pattern
    # as the sqlite bootstrap above — it can't block the calling loop.
    auth_tokens = TokenRegistry()
    seed_tokens_from_settings(effective_settings, auth_tokens)

    if synthesized_sqlite or settings.database_url:
        import asyncio as _asyncio
        import threading as _threading

        from backend.api.auth import hydrate_registry_from_repo

        _hydrate_err: dict[str, BaseException] = {}

        async def _do_hydrate() -> None:
            try:
                await hydrate_registry_from_repo(auth_tokens, token_repo)
            finally:
                await database.engine.dispose()

        def _hydrate_thread() -> None:
            try:
                _asyncio.run(_do_hydrate())
            except BaseException as exc:  # pragma: no cover — defensive
                _hydrate_err["err"] = exc

        t = _threading.Thread(
            target=_hydrate_thread, name="sentry-auth-hydrate", daemon=True,
        )
        t.start()
        t.join()
        if "err" in _hydrate_err:  # pragma: no cover
            logger.warning("auth: token hydrate failed: %s", _hydrate_err["err"])

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
        auth_tokens=auth_tokens,
        token_repo=token_repo,
        secrets=secrets_provider,
        broadcaster=broadcaster,
    )

    logger.info(
        "ServiceContainer built (mode=%s, provider=%s)",
        config.security.mode.value,
        config.llm_provider.value,
    )
    return container


__all__ = ["build_container"]
