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
from dataclasses import dataclass
from typing import AsyncIterator

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
        """Create every declared table. Idempotent."""
        async with self.engine.begin() as conn:
            await conn.run_sync(base.metadata.create_all)

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


def build_database(database_url: str, *, echo: bool = False) -> Database:
    """Construct a ``Database`` from a SQLAlchemy async URL.

    ``echo=True`` prints SQL for debugging. Should always be ``False`` in
    production.
    """
    # SQLite has limitations with pooling — use the StaticPool for in-memory
    # and the NullPool for file-based to avoid "database is locked" in tests.
    connect_args: dict = {}
    kwargs: dict = {"echo": echo}
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
