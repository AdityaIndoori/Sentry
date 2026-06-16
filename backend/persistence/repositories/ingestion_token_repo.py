"""
SaaS foundation — ``IngestionTokenRepository``.

Async CRUD over the ``ingestion_tokens`` table. These are the per-account
keys customers put in their log shippers (a Docker sidecar, a Vector/
Fluent Bit HTTP sink, or a plain ``curl``) so that ``POST /api/ingest``
can attribute incoming log lines to the right tenant.

Only the SHA-256 hash of the raw token is stored — the raw value is
returned exactly once at mint time and shown to the user on the
"Connect a service" onboarding screen.

Resolution (hash -> account_id) is the hot path for ingestion, so it is
a single indexed lookup. Revoked tokens never resolve.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, select, update

from backend.persistence.models import IngestionTokenRow
from backend.persistence.session import Database
from backend.shared.principal import generate_token, hash_token

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MintedIngestionToken:
    """Returned once at mint time — carries the RAW token for display."""

    id: str
    account_id: str
    service_name: str
    raw_token: str


@dataclass(frozen=True)
class StoredIngestionToken:
    """Row snapshot (no raw token)."""

    id: str
    account_id: str
    token_hash: str
    service_name: str
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


class IngestionTokenRepository:
    """Async CRUD over the ``ingestion_tokens`` table."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Mint
    # ------------------------------------------------------------------

    async def mint(self, *, account_id: str, service_name: str = "") -> MintedIngestionToken:
        """Create a new ingestion token for ``account_id``.

        The raw token is generated here, hashed, and only the hash is
        stored. The caller MUST surface ``raw_token`` to the user
        immediately — it cannot be recovered later.
        """
        raw = "sing_" + generate_token(24)
        token_hash = hash_token(raw)
        token_id = token_hash[:12]
        row = IngestionTokenRow(
            id=token_id,
            account_id=account_id,
            token_hash=token_hash,
            service_name=service_name,
            created_at=datetime.now(UTC),
            last_used_at=None,
            revoked_at=None,
        )
        async with self._db.sessionmaker() as session:
            session.add(row)
            await session.commit()
        logger.info(
            "ingestion_tokens: minted id=%s account=%s service=%s",
            token_id, account_id, service_name,
        )
        return MintedIngestionToken(
            id=token_id,
            account_id=account_id,
            service_name=service_name,
            raw_token=raw,
        )

    # ------------------------------------------------------------------
    # Resolve (ingest hot path)
    # ------------------------------------------------------------------

    async def resolve(self, raw_token: str) -> StoredIngestionToken | None:
        """Return the active token row for ``raw_token`` or ``None``.

        Revoked tokens resolve to ``None``. Best-effort updates
        ``last_used_at`` so the dashboard can show "last seen".
        """
        token_hash = hash_token(raw_token)
        async with self._db.sessionmaker() as session:
            stmt = select(IngestionTokenRow).where(IngestionTokenRow.token_hash == token_hash)
            row = (await session.execute(stmt)).scalar_one_or_none()
            if row is None or row.revoked_at is not None:
                return None
            row.last_used_at = datetime.now(UTC)
            await session.commit()
            snapshot = self._to_stored(row)
        return snapshot

    # ------------------------------------------------------------------
    # List / revoke
    # ------------------------------------------------------------------

    async def list_for_account(
        self, account_id: str, *, include_revoked: bool = False
    ) -> list[StoredIngestionToken]:
        async with self._db.sessionmaker() as session:
            stmt = (
                select(IngestionTokenRow)
                .where(IngestionTokenRow.account_id == account_id)
                .order_by(IngestionTokenRow.created_at.asc())
            )
            rows = (await session.execute(stmt)).scalars().all()
        out = [self._to_stored(r) for r in rows]
        if include_revoked:
            return out
        return [t for t in out if not t.is_revoked]

    async def revoke(self, *, account_id: str, token_id: str) -> bool:
        """Revoke a token, but only if it belongs to ``account_id``.

        The account scoping in the WHERE clause prevents one tenant from
        revoking another tenant's token by id-guessing.
        """
        now = datetime.now(UTC)
        async with self._db.sessionmaker() as session:
            stmt = (
                update(IngestionTokenRow)
                .where(IngestionTokenRow.id == token_id)
                .where(IngestionTokenRow.account_id == account_id)
                .where(IngestionTokenRow.revoked_at.is_(None))
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
    def _to_stored(row: IngestionTokenRow) -> StoredIngestionToken:
        return StoredIngestionToken(
            id=row.id,
            account_id=row.account_id,
            token_hash=row.token_hash,
            service_name=row.service_name,
            created_at=row.created_at,
            last_used_at=row.last_used_at,
            revoked_at=row.revoked_at,
        )


__all__ = [
    "IngestionTokenRepository",
    "MintedIngestionToken",
    "StoredIngestionToken",
]
