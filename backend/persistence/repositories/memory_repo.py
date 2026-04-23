"""
P1.2 — ``PostgresMemoryRepo``.

Drop-in replacement for :class:`backend.memory.store.JSONMemoryStore` that
stores memory entries in the ``memory_entries`` table and the system
fingerprint in the ``memory_state`` singleton table. Implements the
existing :class:`backend.shared.interfaces.IMemoryStore` contract so the
orchestrator (and every existing test that exercises memory) keeps
working unchanged.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import delete, select

from backend.persistence.models import MemoryEntryRow, MemoryStateRow
from backend.persistence.session import Database
from backend.shared.interfaces import IMemoryStore
from backend.shared.models import MemoryEntry

logger = logging.getLogger(__name__)

_FINGERPRINT_KEY = "system_fingerprint"


class PostgresMemoryRepo(IMemoryStore):
    """Async repository backed by SQLAlchemy 2.0."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # IMemoryStore
    # ------------------------------------------------------------------

    async def load(self) -> list[MemoryEntry]:
        async with self._db.sessionmaker() as session:
            rows = (
                await session.execute(
                    select(MemoryEntryRow).order_by(MemoryEntryRow.created_at.asc())
                )
            ).scalars().all()
        return [self._row_to_entry(r) for r in rows]

    async def save(self, entry: MemoryEntry) -> None:
        timestamp = entry.timestamp or datetime.now(UTC).isoformat()
        row = MemoryEntryRow(
            id=entry.id,
            symptom=entry.symptom,
            root_cause=entry.root_cause,
            fix=entry.fix,
            vectors=list(entry.vectors or []),
            timestamp=timestamp,
        )
        async with self._db.sessionmaker() as session:
            # If the id already exists, overwrite (same semantics as the
            # JSON store which also allowed append + implicit replace).
            existing = await session.get(MemoryEntryRow, entry.id)
            if existing is not None:
                existing.symptom = entry.symptom
                existing.root_cause = entry.root_cause
                existing.fix = entry.fix
                existing.vectors = list(entry.vectors or [])
                existing.timestamp = timestamp
            else:
                session.add(row)
            await session.commit()
        logger.info("Memory saved (postgres): %s", entry.id)

    async def get_relevant(self, vectors: list[str]) -> list[MemoryEntry]:
        """Return entries whose vectors overlap the query set, most relevant first.

        We do the intersection in application code rather than SQL so the
        same repo works on Postgres, SQLite (JSON1), and MySQL. The table
        is small (max a few thousand rows) so the scan is cheap.
        """
        all_entries = await self.load()
        query_set = set(vectors)
        scored = []
        for e in all_entries:
            overlap = set(e.vectors) & query_set
            if overlap:
                scored.append((len(overlap), e))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [e for _, e in scored]

    async def get_count(self) -> int:
        async with self._db.sessionmaker() as session:
            result = await session.execute(select(MemoryEntryRow.id))
            return len(result.scalars().all())

    async def compact(self, summary_entries: list[MemoryEntry]) -> None:
        """Replace all entries with compacted summaries."""
        async with self._db.sessionmaker() as session:
            await session.execute(delete(MemoryEntryRow))
            for e in summary_entries:
                session.add(
                    MemoryEntryRow(
                        id=e.id,
                        symptom=e.symptom,
                        root_cause=e.root_cause,
                        fix=e.fix,
                        vectors=list(e.vectors or []),
                        timestamp=e.timestamp
                        or datetime.now(UTC).isoformat(),
                    )
                )
            await session.commit()
        logger.info("Memory compacted (postgres): %d entries", len(summary_entries))

    # ------------------------------------------------------------------
    # System fingerprint — stored in memory_state singleton table
    # ------------------------------------------------------------------

    async def set_fingerprint(self, fingerprint: str) -> None:
        async with self._db.sessionmaker() as session:
            existing = await session.get(MemoryStateRow, _FINGERPRINT_KEY)
            if existing is None:
                session.add(MemoryStateRow(key=_FINGERPRINT_KEY, value=fingerprint))
            else:
                existing.value = fingerprint
            await session.commit()

    async def get_fingerprint(self) -> str:
        async with self._db.sessionmaker() as session:
            row = await session.get(MemoryStateRow, _FINGERPRINT_KEY)
            return row.value if row else ""

    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_entry(row: MemoryEntryRow) -> MemoryEntry:
        return MemoryEntry(
            id=row.id,
            symptom=row.symptom,
            root_cause=row.root_cause,
            fix=row.fix,
            vectors=list(row.vectors or []),
            timestamp=row.timestamp,
        )


__all__ = ["PostgresMemoryRepo"]
