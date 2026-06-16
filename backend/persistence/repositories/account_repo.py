"""
SaaS foundation — ``AccountRepository``.

Async CRUD over the ``accounts`` table. Owns the password-hash lifecycle
(delegating the crypto to :mod:`backend.shared.accounts`) so callers
never touch raw hashes. Email lookups are case-insensitive because the
value is normalized before insert and on every lookup.

The repository deliberately returns a frozen :class:`StoredAccount`
snapshot rather than the live ORM row so callers can hold the value
across the async session boundary without lazy-load surprises.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select

from backend.persistence.models import AccountRow
from backend.persistence.session import Database
from backend.shared.accounts import (
    hash_password,
    new_account_id,
    normalize_email,
    verify_password,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StoredAccount:
    """Row snapshot of an :class:`AccountRow`."""

    id: str
    email: str
    password_hash: str
    display_name: str
    default_mode: str
    created_at: datetime
    disabled_at: datetime | None

    @property
    def is_disabled(self) -> bool:
        return self.disabled_at is not None


class AccountRepository:
    """Async CRUD over the ``accounts`` table."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    async def create(
        self,
        *,
        email: str,
        password: str,
        display_name: str = "",
        default_mode: str = "audit",
    ) -> StoredAccount:
        """Create a new account. Raises ``ValueError`` if the email is taken.

        The password is hashed here; the raw value is never persisted.
        """
        norm = normalize_email(email)
        existing = await self.get_by_email(norm)
        if existing is not None:
            raise ValueError("email_taken")
        row = AccountRow(
            id=new_account_id(),
            email=norm,
            password_hash=hash_password(password),
            display_name=display_name or norm.split("@", 1)[0],
            default_mode=default_mode,
            created_at=datetime.now(UTC),
            disabled_at=None,
        )
        async with self._db.sessionmaker() as session:
            session.add(row)
            await session.commit()
            await session.refresh(row)
        logger.info("accounts: created id=%s email=%s", row.id, norm)
        return self._to_stored(row)

    # ------------------------------------------------------------------
    # SSO provisioning (Cloudflare Access)
    # ------------------------------------------------------------------

    async def get_or_create_sso(self, email: str) -> StoredAccount:
        """Return the account for ``email``, creating it if absent.

        Used by the Cloudflare Access auth path: the identity is proven
        by Cloudflare's signed JWT, so there is no password. We store a
        sentinel ``password_hash`` that ``verify_password`` can never
        match (so the password-login endpoint can't be used for an
        SSO-provisioned account). Idempotent + race-safe: a concurrent
        insert that loses the unique-email race falls back to a lookup.
        """
        norm = normalize_email(email)
        existing = await self.get_by_email(norm)
        if existing is not None:
            return existing
        row = AccountRow(
            id=new_account_id(),
            email=norm,
            password_hash="sso:cloudflare-access",  # never verifies
            display_name=norm.split("@", 1)[0],
            default_mode="audit",
            created_at=datetime.now(UTC),
            disabled_at=None,
        )
        try:
            async with self._db.sessionmaker() as session:
                session.add(row)
                await session.commit()
                await session.refresh(row)
            logger.info("accounts: SSO-provisioned id=%s email=%s", row.id, norm)
            return self._to_stored(row)
        except Exception:
            # Lost the unique-email race (or other integrity error) —
            # re-read; the winning insert is now visible.
            again = await self.get_by_email(norm)
            if again is not None:
                return again
            raise

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get(self, account_id: str) -> StoredAccount | None:
        async with self._db.sessionmaker() as session:
            row = await session.get(AccountRow, account_id)
        return self._to_stored(row) if row else None

    async def get_by_email(self, email: str) -> StoredAccount | None:
        norm = normalize_email(email)
        async with self._db.sessionmaker() as session:
            stmt = select(AccountRow).where(AccountRow.email == norm)
            row = (await session.execute(stmt)).scalar_one_or_none()
        return self._to_stored(row) if row else None

    # ------------------------------------------------------------------
    # Authenticate
    # ------------------------------------------------------------------

    async def authenticate(self, email: str, password: str) -> StoredAccount | None:
        """Return the account iff email+password match and it's enabled.

        Always runs the (slow) verify even on a missing account so the
        timing does not reveal whether the email exists.
        """
        account = await self.get_by_email(email)
        if account is None:
            # Burn a hash to equalize timing against the hit path.
            verify_password(password, hash_password("__no_such_account__"))
            return None
        if account.is_disabled:
            return None
        if not verify_password(password, account.password_hash):
            return None
        return account

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_stored(row: AccountRow) -> StoredAccount:
        return StoredAccount(
            id=row.id,
            email=row.email,
            password_hash=row.password_hash,
            display_name=row.display_name,
            default_mode=row.default_mode,
            created_at=row.created_at,
            disabled_at=row.disabled_at,
        )


__all__ = ["AccountRepository", "StoredAccount"]
