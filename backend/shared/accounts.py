"""
SaaS foundation — Account identity + password primitives.

Sentry's pre-SaaS auth used *opaque bearer tokens* minted by an
operator (see :mod:`backend.shared.principal` + :mod:`backend.api.auth`).
To become a multi-tenant SaaS we add the concept of an **Account** —
an end-user who signs up with an email + password and then owns a set
of *ingestion tokens* (for shipping their service logs) and a *session
token* (a bearer token the dashboard SPA stores after login).

This module is deliberately dependency-free: password hashing uses
``hashlib.pbkdf2_hmac`` from the stdlib so we do not pull in
``bcrypt`` / ``argon2`` / ``passlib`` just to ship the first cut. The
hash format is self-describing (``pbkdf2_sha256$<iters>$<salt>$<hash>``)
so a future migration to argon2 can detect-and-rehash on next login.

The :class:`Principal` machinery is reused unchanged: a logged-in
account resolves to a ``Principal`` whose ``id`` is the account id and
whose ``account_id`` attribute scopes every incident / memory row that
the request touches. This keeps the existing scope-gate + middleware
hot path identical — multi-tenancy rides on the same rails.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid

# PBKDF2 parameters. 600k iterations of SHA-256 is the OWASP 2023
# floor; raise as hardware improves. The format string embeds the
# iteration count so old hashes stay verifiable after a bump.
_PBKDF2_ITERATIONS = 600_000
_PBKDF2_ALGO = "sha256"
_HASH_PREFIX = "pbkdf2_sha256"

# Pragmatic email shape check — full RFC 5322 validation is a rabbit
# hole; this rejects the obvious garbage and we rely on a verification
# email (future work) for real deliverability.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Minimum password length. Kept modest so the onboarding flow is not
# hostile; the real defense is the slow PBKDF2 hash + rate limiting.
MIN_PASSWORD_LENGTH = 8


def normalize_email(email: str) -> str:
    """Lower-case + strip an email so lookups are case-insensitive."""
    return (email or "").strip().lower()


def is_valid_email(email: str) -> bool:
    """Cheap structural validation of an email address."""
    return bool(_EMAIL_RE.match(normalize_email(email)))


def hash_password(password: str, *, iterations: int = _PBKDF2_ITERATIONS) -> str:
    """Return a self-describing PBKDF2 hash for ``password``.

    Format: ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>``. The
    salt is 16 random bytes; the derived key is 32 bytes.
    """
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode("utf-8"), salt, iterations)
    return f"{_HASH_PREFIX}${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify ``password`` against a stored PBKDF2 hash.

    Returns ``False`` (never raises) on any malformed stored value so a
    corrupted row can't crash the login path.
    """
    try:
        prefix, iters_s, salt_hex, hash_hex = stored.split("$", 3)
        if prefix != _HASH_PREFIX:
            return False
        iterations = int(iters_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False
    dk = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(dk, expected)


def new_account_id() -> str:
    """Mint a stable, opaque account identifier."""
    return "acct_" + uuid.uuid4().hex[:24]


def validate_signup(email: str, password: str) -> str | None:
    """Return an error string if signup inputs are invalid, else ``None``."""
    if not is_valid_email(email):
        return "A valid email address is required."
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    return None


__all__ = [
    "MIN_PASSWORD_LENGTH",
    "hash_password",
    "is_valid_email",
    "new_account_id",
    "normalize_email",
    "validate_signup",
    "verify_password",
]
