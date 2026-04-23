"""
P1.2 — ``PostgresAuditLog``.

Drop-in replacement for :class:`backend.shared.audit_log.ImmutableAuditLog`
that persists hash-chained audit rows to the ``audit_log`` table. The
hash chain is identical to the file-based version so
``verify_integrity()`` still works.

The class exposes a **synchronous** ``log_action()`` method on purpose —
the rest of the codebase (agents, tools, engine) calls
``audit_log.log_action(...)`` in hot paths without awaiting, so we keep
that semantics by running a tiny async block inside an event loop. When
called from within an async task this takes the currently-running loop
and schedules the write via ``asyncio.run_coroutine_threadsafe`` if
needed; when called from sync code it opens a short-lived loop. This
mirrors the behavior of the JSONL implementation which also wrote
synchronously to the filesystem from any caller.

Integrity contract preserved
----------------------------
* ``prev_hash`` of a new entry = ``entry_hash`` of the most recent row.
* ``entry_hash`` = SHA-256 of the entry dict with ``entry_hash`` removed,
  serialized with ``sort_keys=True, separators=(',',':')`` — same as the
  legacy file impl.
* Reads never mutate the hash chain; ``verify_integrity()`` recomputes
  each row's hash and compares.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import threading
from collections.abc import Coroutine
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from backend.persistence.models import AuditLogRow
from backend.persistence.session import Database

logger = logging.getLogger(__name__)

_GENESIS = "genesis"


class PostgresAuditLog:
    """Hash-chained audit log stored in Postgres / SQLite.

    Public API mirrors :class:`ImmutableAuditLog` so callers don't change.
    """

    def __init__(self, db: Database) -> None:
        self._db = db
        self._lock = threading.Lock()
        # _last_hash is cached in memory to avoid a round-trip per log
        # call. It is initialized lazily from the DB on first
        # log_action()/verify_integrity().
        self._last_hash: str | None = None

    # ------------------------------------------------------------------
    # Sync entrypoints (matches ImmutableAuditLog)
    # ------------------------------------------------------------------

    def log_action(
        self,
        agent_id: str,
        action: str,
        detail: str,
        result: str,
        chain_of_thought: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Append one immutable entry. Returns the new entry_hash."""
        with self._lock:
            prev = self._last_hash if self._last_hash is not None else self._sync_get_last_hash()

            entry: dict[str, Any] = {
                "timestamp": datetime.now(UTC).isoformat(),
                "agent_id": agent_id,
                "action": action,
                "detail": detail,
                "result": result,
                "chain_of_thought": chain_of_thought,
                "metadata": metadata or {},
                "prev_hash": prev,
            }
            entry_hash = _compute_hash(entry)
            entry["entry_hash"] = entry_hash

            _run_sync(
                self._persist_entry(entry),
                label=f"audit.log_action({action})",
            )

            self._last_hash = entry_hash
            return entry_hash

    def read_all(self) -> list[dict[str, Any]]:
        result = _run_sync(self._read_all_async(), label="audit.read_all")
        return result if result is not None else []

    def verify_integrity(self) -> bool:
        entries = self.read_all()
        if not entries:
            return True

        prev_hash = _GENESIS
        for i, entry in enumerate(entries):
            if entry.get("prev_hash") != prev_hash:
                logger.error(
                    "INTEGRITY VIOLATION at entry %d: prev_hash mismatch", i
                )
                return False
            stored_hash = entry.pop("entry_hash", "")
            computed = _compute_hash(entry)
            entry["entry_hash"] = stored_hash
            if computed != stored_hash:
                logger.error("INTEGRITY VIOLATION at entry %d: hash mismatch", i)
                return False
            prev_hash = stored_hash
        return True

    def get_entry_count(self) -> int:
        return len(self.read_all())

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _sync_get_last_hash(self) -> str:
        h = _run_sync(self._fetch_last_hash(), label="audit.last_hash")
        if h is None:
            h = _GENESIS
        self._last_hash = h
        return h

    async def _fetch_last_hash(self) -> str:
        async with self._db.sessionmaker() as session:
            row = (
                await session.execute(
                    select(AuditLogRow.entry_hash)
                    .order_by(AuditLogRow.id.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            return row if row else _GENESIS

    async def _persist_entry(self, entry: dict[str, Any]) -> None:
        async with self._db.sessionmaker() as session:
            session.add(
                AuditLogRow(
                    timestamp=datetime.fromisoformat(entry["timestamp"]),
                    timestamp_iso=entry["timestamp"],
                    agent_id=entry["agent_id"],
                    action=entry["action"],
                    detail=entry["detail"],
                    result=entry["result"],
                    chain_of_thought=entry["chain_of_thought"],
                    extra_metadata=entry["metadata"],
                    prev_hash=entry["prev_hash"],
                    entry_hash=entry["entry_hash"],
                )
            )
            await session.commit()

    async def _read_all_async(self) -> list[dict[str, Any]]:
        async with self._db.sessionmaker() as session:
            rows = (
                await session.execute(
                    select(AuditLogRow).order_by(AuditLogRow.id.asc())
                )
            ).scalars().all()
        return [self._row_to_dict(r) for r in rows]

    @staticmethod
    def _row_to_dict(row: AuditLogRow) -> dict[str, Any]:
        # Use the exact ISO string that was hashed at log_action() time.
        # Reconstituting the DateTime -> isoformat() can change precision
        # or timezone formatting (e.g. "+00:00" vs "Z"), breaking the
        # hash. ``timestamp_iso`` is the authoritative copy.
        return {
            "timestamp": row.timestamp_iso,
            "agent_id": row.agent_id,
            "action": row.action,
            "detail": row.detail,
            "result": row.result,
            "chain_of_thought": row.chain_of_thought,
            "metadata": row.extra_metadata or {},
            "prev_hash": row.prev_hash,
            "entry_hash": row.entry_hash,
        }


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _compute_hash(entry: dict[str, Any]) -> str:
    payload = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _run_sync[T](coro: Coroutine[Any, Any, T], *, label: str) -> T | None:
    """Run an async coroutine from a sync caller.

    Works from both non-async code and from within a live event loop:
    when inside an event loop we run the coroutine on a new loop in a
    worker thread so we don't deadlock the caller's loop.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Another loop is live — spin a worker thread with its own loop.
            result_box: dict[str, T] = {}
            error_box: dict[str, BaseException] = {}

            def runner() -> None:
                try:
                    result_box["v"] = asyncio.run(coro)
                except Exception as exc:  # pragma: no cover
                    error_box["e"] = exc

            t = threading.Thread(target=runner, name=f"audit-{label}", daemon=True)
            t.start()
            t.join()
            if "e" in error_box:
                raise error_box["e"]
            return result_box.get("v")
    except RuntimeError:
        # No running loop at all — fall through to asyncio.run.
        pass
    return asyncio.run(coro)


__all__ = ["PostgresAuditLog"]
