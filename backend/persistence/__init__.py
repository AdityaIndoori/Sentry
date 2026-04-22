"""
P1.2 — Persistence layer.

SQLAlchemy 2.0 async ORM + Alembic migrations. Supports Postgres
(via asyncpg in production) and SQLite (via aiosqlite for local dev
and CI without a running Postgres).

The module is import-safe even when SQLAlchemy isn't installed — the
only thing the legacy code path needs from this package is the
``PostgresMemoryRepo`` class, which we only ever import when
``Settings.database_url`` is set. ``backend.shared.factory.build_container``
performs that conditional import.
"""
