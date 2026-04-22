"""
P1.2 — Alembic migration environment.

Reads the database URL from ``DATABASE_URL`` (or ``backend.shared.settings.get_settings()``)
rather than the static ``alembic.ini`` value, so rotating creds or
switching between Postgres and SQLite doesn't require editing the config
file.

Usage
-----
``alembic -c backend/persistence/alembic.ini upgrade head``

The ``app.py`` lifespan does NOT call this — production images run the
upgrade as a one-shot container (``docker compose run --rm backend
alembic upgrade head``) so migrations are a deliberate step.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import AsyncEngine

from backend.persistence.models import Base
from backend.persistence.session import build_database

# Alembic Config object — provides access to values in alembic.ini.
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for autogenerate support.
target_metadata = Base.metadata


def _resolve_database_url() -> str:
    """Pick the DB URL from DATABASE_URL env var, falling back to alembic.ini."""
    env_url = os.environ.get("DATABASE_URL")
    if env_url:
        return env_url
    url = config.get_main_option("sqlalchemy.url")
    if not url:
        raise RuntimeError(
            "Alembic: neither DATABASE_URL env var nor alembic.ini "
            "sqlalchemy.url is set. Refusing to run migrations."
        )
    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — emits SQL to stdout, no DB connection."""
    url = _resolve_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=url.startswith("sqlite"),  # SQLite needs batch mode
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode using the async engine."""
    database = build_database(_resolve_database_url())
    engine: AsyncEngine = database.engine

    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
