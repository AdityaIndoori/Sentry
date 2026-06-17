"""
P1.2 — Async SQLAlchemy engine + session factory.

Accepts any SQLAlchemy async URL:

* ``postgresql+asyncpg://user:pass@host:5432/db`` — production
* ``sqlite+aiosqlite:///path/to/sentry.db`` — local dev / CI
* ``sqlite+aiosqlite:///:memory:`` — unit tests

The factory is lazy: a ``Database`` instance stores the engine + session
maker but connects on first query. Call ``create_all(Base)`` to
bootstrap the schema (used in tests where Alembic is overkill).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from backend.persistence.models import Base

logger = logging.getLogger(__name__)


@dataclass
class Database:
    """Holds the async engine + session maker for one process.

    Exactly one of these should exist per ``ServiceContainer``; it is
    disposed as part of ``ServiceContainer.shutdown()``.
    """

    engine: AsyncEngine
    sessionmaker: async_sessionmaker[AsyncSession]
    url: str

    async def create_all(self, base: type[DeclarativeBase] = Base) -> None:
        """Create every declared table. Idempotent.

        After the tables exist, the Postgres ``audit_log`` immutability
        triggers are installed imperatively via ``exec_driver_sql`` (one
        statement at a time). This deliberately sidesteps SQLAlchemy's
        ``after_create`` DDL events for Postgres: asyncpg routes
        ``connection.execute(DDL)`` through the extended-query protocol,
        which rejects a PL/pgSQL ``CREATE FUNCTION`` body and surfaces the
        misleading ``syntax error at or near "table"``. ``exec_driver_sql``
        uses the simple-query protocol, which accepts the dollar-quoted
        function body. SQLite triggers are still handled by ``after_create``
        listeners in ``models.py``.
        """
        from backend.persistence.models import PG_AUDIT_TRIGGER_STATEMENTS

        async with self.engine.begin() as conn:
            await conn.run_sync(base.metadata.create_all)
            if conn.dialect.name == "postgresql":
                for stmt in PG_AUDIT_TRIGGER_STATEMENTS:
                    await conn.exec_driver_sql(stmt)


    async def drop_all(self, base: type[DeclarativeBase] = Base) -> None:
        """Drop every declared table — ONLY used by tests."""
        async with self.engine.begin() as conn:
            await conn.run_sync(base.metadata.drop_all)

    async def dispose(self) -> None:
        """Close all connections in the pool."""
        await self.engine.dispose()

    def session(self) -> AsyncIterator[AsyncSession]:
        """FastAPI/test-style dependency that yields one session."""
        async def _scope() -> AsyncIterator[AsyncSession]:
            async with self.sessionmaker() as session:
                yield session

        return _scope()


def _normalize_async_url(database_url: str) -> str:
    """Coerce a DB URL to an async-driver SQLAlchemy URL.

    Managed Postgres providers (Render, Heroku, Fly, …) hand out a plain
    ``postgresql://`` (or legacy ``postgres://``) connection string, which
    SQLAlchemy maps to the *sync* ``psycopg2`` driver — not installed in
    this image (we ship ``asyncpg``). Rewrite the scheme to
    ``postgresql+asyncpg://`` so ``create_async_engine`` picks asyncpg.

    Also drop a trailing ``?sslmode=...`` query param: that's libpq/psycopg
    syntax which asyncpg rejects. asyncpg negotiates TLS automatically for
    managed providers, so dropping it is safe.
    """
    url = database_url
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+asyncpg://" + url[len("postgresql://"):]
    # asyncpg doesn't understand libpq's ``sslmode`` query parameter.
    if url.startswith("postgresql+asyncpg://") and "sslmode=" in url:
        base, _, query = url.partition("?")
        kept = "&".join(
            p for p in query.split("&") if p and not p.startswith("sslmode=")
        )
        url = f"{base}?{kept}" if kept else base
    return url


def build_database(database_url: str, *, echo: bool = False) -> Database:
    """Construct a ``Database`` from a SQLAlchemy async URL.

    ``echo=True`` prints SQL for debugging. Should always be ``False`` in
    production. The URL is normalized to an async driver first so a bare
    ``postgresql://`` from a managed provider still uses asyncpg.
    """
    database_url = _normalize_async_url(database_url)
    # SQLite has limitations with pooling — use the StaticPool for in-memory
    # and the NullPool for file-based to avoid "database is locked" in tests.
    connect_args: dict[str, Any] = {}
    kwargs: dict[str, Any] = {"echo": echo}
    if database_url.startswith("sqlite"):
        # aiosqlite ignores check_same_thread, but harmless
        connect_args["check_same_thread"] = False
        kwargs["connect_args"] = connect_args

    engine = create_async_engine(database_url, **kwargs)
    sessionmaker = async_sessionmaker(
        engine, expire_on_commit=False, class_=AsyncSession
    )
    logger.info("persistence database configured: %s", _safe_url(database_url))
    return Database(engine=engine, sessionmaker=sessionmaker, url=database_url)


def _safe_url(url: str) -> str:
    """Redact the password component of a DB URL for logging."""
    if "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    if "@" in rest and ":" in rest.split("@", 1)[0]:
        creds, tail = rest.split("@", 1)
        user = creds.split(":", 1)[0]
        return f"{scheme}://{user}:***@{tail}"
    return url


__all__ = ["Database", "build_database"]
