"""
E2E test fixtures: a live Sentry stack with the orchestrator, tool executor,
memory store, and FastAPI app all wired together against an isolated tmpdir —
no Docker, no Postgres (until P1.2), no Anthropic API.

The LLM is a scripted ``FakeLLMClient`` (see ``fake_llm.py``). Every other
layer (security, vault, audit log, tool registry, throttle, circuit
breaker, watcher, engine, FastAPI routes) is the REAL production class so
the contract coverage is real.

P1.1 update
-----------
We now reuse the canonical composition root
:func:`backend.shared.factory.build_container` and the real
:func:`backend.api.app.create_app` factory. The previous hand-rolled
in-process FastAPI app has been deleted — tests drive the same routes
that production does, through a ServiceContainer attached to
``app.state.container``.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx
import pytest
from fastapi import FastAPI

from backend.api.app import create_app
from backend.shared.container import ServiceContainer
from backend.shared.config import (
    AppConfig,
    MemoryConfig,
    SecurityConfig,
    SentryMode,
    WatcherConfig,
)
from backend.shared.factory import build_container
from backend.shared.security import SecurityGuard
from backend.shared.settings import Settings

from backend.tests.e2e.fake_llm import FakeLLMClient, resolving_llm


# ──────────────────────────────────────────────────────────────────────
# Gate: all e2e tests require SENTRY_E2E=1. Saves 30+ seconds in the
# normal dev loop while still being runnable via `SENTRY_E2E=1 pytest`.
# ──────────────────────────────────────────────────────────────────────

_E2E_ENABLED = os.environ.get("SENTRY_E2E", "").lower() in {"1", "true", "yes"}
e2e = pytest.mark.skipif(not _E2E_ENABLED, reason="E2E gated — set SENTRY_E2E=1")


# ──────────────────────────────────────────────────────────────────────
# LiveStack — a thin facade over ServiceContainer that preserves the
# pre-P1.1 attribute surface so the 30+ existing e2e tests keep working
# without a sweeping rename. New tests should pull services directly
# from ``.container``.
# ──────────────────────────────────────────────────────────────────────


@dataclass
class LiveStack:
    container: ServiceContainer
    root: Path = field(default_factory=Path)

    # --- attribute passthroughs to keep the legacy test API stable ----
    @property
    def config(self) -> AppConfig:
        return self.container.config

    @property
    def settings(self) -> Settings:
        return self.container.settings

    @property
    def vault(self):
        return self.container.vault

    @property
    def gateway(self):
        return self.container.gateway

    @property
    def audit_log(self):
        return self.container.audit_log

    @property
    def throttle(self):
        return self.container.throttle

    @property
    def registry(self):
        return self.container.registry

    @property
    def security(self) -> SecurityGuard:
        return self.container.security

    @property
    def memory(self):
        return self.container.memory

    @property
    def tools(self):
        return self.container.tools

    @property
    def llm(self) -> FakeLLMClient:
        return self.container.llm  # type: ignore[return-value]

    @property
    def circuit_breaker(self):
        return self.container.circuit_breaker

    @property
    def orchestrator(self):
        return self.container.orchestrator

    @property
    def watcher(self):
        return self.container.watcher

    async def shutdown(self) -> None:
        await self.container.shutdown()


def _build_settings_for_tmp(tmp_root: Path, mode: SentryMode,
                            watch_paths: Optional[tuple]) -> Settings:
    """Produce a Settings instance pointing at the per-test tmpdir."""
    (tmp_root / "workspace").mkdir(exist_ok=True)
    (tmp_root / "workspace" / "config").mkdir(exist_ok=True)
    (tmp_root / "data").mkdir(exist_ok=True)
    (tmp_root / "watched").mkdir(exist_ok=True)
    (tmp_root / "patchable").mkdir(exist_ok=True)

    (tmp_root / "workspace" / "config" / "db.py").write_text(
        "DB_HOST = 'localhost'\nDB_PORT = 5432\n", encoding="utf-8"
    )
    (tmp_root / "workspace" / "app.py").write_text(
        "# placeholder service\n", encoding="utf-8"
    )

    paths = watch_paths or (str(tmp_root / "watched" / "*.log"),)

    # Settings is a frozen dataclass; constructed directly here so tests
    # don't mutate process env. We only override the fields we care
    # about — every other field keeps its default.
    return Settings(
        mode=mode,
        environment="test",
        log_level="INFO",
        stop_file_path=str(tmp_root / "STOP_SENTRY"),
        project_root=str(tmp_root / "workspace"),
        patchable_root=str(tmp_root / "patchable"),
        service_source_path=str(tmp_root / "workspace"),
        audit_log_path=str(tmp_root / "data" / "audit.jsonl"),
        memory_file_path=str(tmp_root / "data" / "memory.json"),
        memory_max_incidents_before_compaction=50,
        watch_paths=paths,
        poll_interval_seconds=0.05,  # fast for tests
    )


def build_live_stack(tmp_root: Path, llm: Optional[FakeLLMClient] = None,
                     mode: SentryMode = SentryMode.AUDIT,
                     watch_paths: Optional[tuple] = None) -> LiveStack:
    """Construct a fully-wired in-process Sentry stack for E2E tests.

    Delegates to the canonical
    :func:`backend.shared.factory.build_container` with a fake LLM
    override — same composition root production uses.
    """
    settings = _build_settings_for_tmp(tmp_root, mode, watch_paths)
    container = build_container(settings, llm_override=llm or resolving_llm())

    # Memory store writes need to be configured to skip backups
    # (tests in tmpdir). We re-create just the memory store with
    # backup_on_write=False so the scratch dir stays tidy.
    from backend.memory.store import JSONMemoryStore
    container.memory = JSONMemoryStore(MemoryConfig(
        file_path=container.config.memory.file_path,
        backup_on_write=False,
        max_incidents_before_compaction=container.config.memory.max_incidents_before_compaction,
    ))
    # Rewire the orchestrator's memory pointer to the new store.
    container.orchestrator._memory = container.memory

    return LiveStack(container=container, root=tmp_root)


# ──────────────────────────────────────────────────────────────────────
# pytest fixtures
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def e2e_tmpdir(tmp_path: Path) -> Path:
    """A test-scoped workspace directory populated with a minimal service."""
    return tmp_path


@pytest.fixture
def stack(e2e_tmpdir: Path) -> LiveStack:
    """A LiveStack using the default resolving_llm."""
    s = build_live_stack(e2e_tmpdir)
    yield s
    asyncio.get_event_loop().run_until_complete(s.shutdown())


@pytest.fixture
def live_stack_factory(e2e_tmpdir: Path):
    """Factory for tests that need custom LLM scripts or modes."""
    created: list[LiveStack] = []

    def _make(llm: Optional[FakeLLMClient] = None,
              mode: SentryMode = SentryMode.AUDIT,
              watch_paths: Optional[tuple] = None) -> LiveStack:
        s = build_live_stack(e2e_tmpdir, llm=llm, mode=mode, watch_paths=watch_paths)
        created.append(s)
        return s

    yield _make

    loop = asyncio.get_event_loop()
    for s in created:
        try:
            loop.run_until_complete(s.shutdown())
        except Exception:  # pragma: no cover
            pass


# ──────────────────────────────────────────────────────────────────────
# In-process FastAPI client — drives the REAL app via create_app(container)
# ──────────────────────────────────────────────────────────────────────


def _build_inprocess_app(stack: LiveStack) -> FastAPI:
    """Return a real FastAPI app pre-wired to this stack's container.

    Post-P1.1 this is a two-liner: we just hand the container to
    :func:`backend.api.app.create_app`. All routes the dashboard calls
    are exercised exactly as they run in production.
    """
    return create_app(container=stack.container)


@pytest.fixture
def api_client(stack: LiveStack):
    """An httpx.AsyncClient talking to the in-process FastAPI app."""
    app = _build_inprocess_app(stack)
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
    yield client
    asyncio.get_event_loop().run_until_complete(client.aclose())


@pytest.fixture
def api_client_factory(live_stack_factory):
    """Factory: `api_client_factory(stack)` returns a client for a specific stack."""
    created: list[httpx.AsyncClient] = []

    def _make(stack: LiveStack) -> httpx.AsyncClient:
        app = _build_inprocess_app(stack)
        transport = httpx.ASGITransport(app=app)
        client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
        created.append(client)
        return client

    yield _make

    loop = asyncio.get_event_loop()
    for c in created:
        try:
            loop.run_until_complete(c.aclose())
        except Exception:  # pragma: no cover
            pass
