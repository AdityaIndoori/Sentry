"""
P2.1 — Principal.

The API has two kinds of callers:

1. **Human operators** (or the dashboard on their behalf) talking to
   `/api/trigger`, `/api/watcher/*`, and the read endpoints.
2. **No caller at all** — the local dev use case where the backend runs
   against ``.env`` with no auth token configured. P2.1 makes that
   ergonomic by auto-disabling auth when the ``ServiceContainer`` has
   an empty token registry.

When auth IS enabled, every authenticated request carries a :class:`Principal`
on ``request.state.principal`` describing *who is calling* and *what
scopes they hold*. Scope strings are namespaced:

* ``incidents:read`` — list / fetch incidents, memory, config, security.
* ``incidents:trigger`` — POST /api/trigger.
* ``watcher:control`` — POST /api/watcher/start|stop.

A token with scope ``"*"`` (admin) matches any requested scope.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True)
class Principal:
    """An authenticated caller.

    Attributes
    ----------
    id:
        Stable identifier (SHA-256 of the raw token, truncated). Used in
        audit logs; never the raw token itself.
    name:
        Human-readable label for ops output (``"dashboard"``,
        ``"ci-bot"``, etc.).
    role:
        Free-form role label (``"admin"`` / ``"operator"`` / ``"read_only"``).
    scopes:
        The exact scopes granted to this token, as a frozenset. The
        special value ``"*"`` in ``scopes`` grants all scopes.
    issued_at:
        When the token was minted. Informational.
    """

    id: str
    name: str
    role: str
    scopes: frozenset[str]
    issued_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def has_scope(self, scope: str) -> bool:
        """Return True iff this Principal is authorized for ``scope``.

        Admins (scope ``"*"``) are authorized for every scope.
        """
        if "*" in self.scopes:
            return True
        return scope in self.scopes


def hash_token(raw_token: str) -> str:
    """Deterministic, collision-resistant fingerprint of a raw bearer token.

    Used both as the registry key (so tokens are never stored in plain
    text in memory) and as ``Principal.id`` (so audit entries reference
    the same identifier regardless of who's reading the log).
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    """Shim around :func:`hmac.compare_digest` that accepts ``str`` / ``bytes``."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def generate_token(nbytes: int = 32) -> str:
    """Mint a fresh, URL-safe bearer token.

    The output is ``secrets.token_urlsafe(nbytes)`` — 32 bytes of entropy
    renders to roughly 43 characters. This is the only recommended way to
    produce a new token; handing a raw string directly is accepted too
    for environments where the operator pre-configured one via env var.
    """
    return secrets.token_urlsafe(nbytes)


__all__ = [
    "Principal",
    "constant_time_equals",
    "generate_token",
    "hash_token",
]
