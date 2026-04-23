"""
P4.2 — ``TokenRepository``.

Persistent backing store for API bearer tokens. The in-memory
:class:`backend.api.auth.TokenRegistry` stays the authoritative runtime
view (lookups must be O(1) and lock-free on the hot path), but at
startup it is *hydrated* from this repo, and admin operations
(mint / revoke / list) go through the repo so state survives restarts.

What we persist
---------------
Only the :class:`~backend.persistence.models.ApiTokenRow` fields:

* ``id`` — short stable identifier (first 12 chars of the token hash).
* ``token_hash`` — ``hashlib.sha256`` of the raw token. The raw token
  is **never** stored. When an operator loses a token they must mint
  a new one — there is no "password reset" flow.
* ``name`` — human-friendly label (``"grafana-dashboard"``, ...).
* ``role`` — one of ``"admin" | "operator" | "read_only"``.
* ``scopes`` — JSON list of scope strings (e.g. ``["incidents:read"]``)
  or ``["*"]`` for admin wildcard.
* ``created_at`` / ``revoked_at`` — timestamps.

Why a separate repo
-------------------
Keeping this logic out of ``TokenRegistry`` preserves the invariant that
the registry is a pure in-memory data structure — no I/O, no async —
which is what the middleware hot path needs. The repo is called only
at boot, during admin mutations, and by the CLI.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, select, update

from backend.persistence.models import ApiTokenRow
from backend.persistence.session import Database

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StoredToken:
    """Row snapshot returned by ``TokenRepository.list_active``.

    Intentionally a frozen dataclass (not the ORM row) so callers can
    pass it across the async boundary without worrying about session
    lifetime.
    """

    id: str
    token_hash: str
    name: str
    role: str
    scopes: tuple[str, ...]
    created_at: datetime
    revoked_at: datetime | None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


class TokenRepository:
    """Async CRUD over the ``api_tokens`` table."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Create / mint
    # ------------------------------------------------------------------

    async def create(
        self,
        *,
        token_id: str,
        token_hash: str,
        name: str,
        role: str,
        scopes: Sequence[str],
    ) -> StoredToken:
        """Insert a new token row. The caller owns the raw token — we
        only ever persist the hash.

        Raises ``IntegrityError`` (propagated from SQLAlchemy) if the
        ``token_id`` or ``token_hash`` already exists, which serves as
        a collision detector for the 12-char id prefix.
        """
        row = ApiTokenRow(
            id=token_id,
            token_hash=token_hash,
            name=name,
            role=role,
            scopes=list(scopes),
            created_at=datetime.now(UTC),
            revoked_at=None,
        )
        async with self._db.sessionmaker() as session:
            session.add(row)
            await session.commit()
            await session.refresh(row)
        logger.info(
            "api_tokens: created id=%s name=%s role=%s scopes=%s",
            token_id, name, role, list(scopes),
        )
        return self._row_to_stored(row)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get(self, token_id: str) -> StoredToken | None:
        async with self._db.sessionmaker() as session:
            row = await session.get(ApiTokenRow, token_id)
        return self._row_to_stored(row) if row else None

    async def get_by_hash(self, token_hash: str) -> StoredToken | None:
        async with self._db.sessionmaker() as session:
            stmt = select(ApiTokenRow).where(ApiTokenRow.token_hash == token_hash)
            row = (await session.execute(stmt)).scalar_one_or_none()
        return self._row_to_stored(row) if row else None

    async def list_all(self, *, include_revoked: bool = False) -> list[StoredToken]:
        async with self._db.sessionmaker() as session:
            stmt = select(ApiTokenRow).order_by(ApiTokenRow.created_at.asc())
            rows = (await session.execute(stmt)).scalars().all()
        out = [self._row_to_stored(r) for r in rows]
        if include_revoked:
            return out
        return [t for t in out if not t.is_revoked]

    # ------------------------------------------------------------------
    # Revoke
    # ------------------------------------------------------------------

    async def revoke(self, token_id: str) -> bool:
        """Mark ``token_id`` as revoked. Returns True if a row was updated."""
        now = datetime.now(UTC)
        async with self._db.sessionmaker() as session:
            stmt = (
                update(ApiTokenRow)
                .where(ApiTokenRow.id == token_id)
                .where(ApiTokenRow.revoked_at.is_(None))
                .values(revoked_at=now)
                .execution_options(synchronize_session=False)
            )
            result = cast(CursorResult[Any], await session.execute(stmt))
            await session.commit()
        updated = result.rowcount or 0
        if updated:
            logger.info("api_tokens: revoked id=%s", token_id)
        return bool(updated)

    async def revoke_by_hash(self, token_hash: str) -> bool:
        """Alternative revocation path keyed by token_hash."""
        now = datetime.now(UTC)
        async with self._db.sessionmaker() as session:
            stmt = (
                update(ApiTokenRow)
                .where(ApiTokenRow.token_hash == token_hash)
                .where(ApiTokenRow.revoked_at.is_(None))
                .values(revoked_at=now)
                .execution_options(synchronize_session=False)
            )
            result = cast(CursorResult[Any], await session.execute(stmt))
            await session.commit()
        return bool(result.rowcount or 0)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_stored(row: ApiTokenRow) -> StoredToken:
        return StoredToken(
            id=row.id,
            token_hash=row.token_hash,
            name=row.name,
            role=row.role,
            scopes=tuple(row.scopes or ()),
            created_at=row.created_at,
            revoked_at=row.revoked_at,
        )


__all__ = ["StoredToken", "TokenRepository"]
