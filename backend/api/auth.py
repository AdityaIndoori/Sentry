"""
P2.1 — Bearer-token authentication for the Sentry API.

This module provides four things:

1. :class:`TokenRegistry` — the in-process mapping of
   ``sha256(raw_token) -> Principal`` plus a revocation set. Lives on
   the :class:`~backend.shared.container.ServiceContainer` as
   ``container.auth_tokens``.
2. :class:`AuthMiddleware` — a Starlette middleware that runs before
   every request, checks the ``Authorization: Bearer <token>`` header,
   rejects bad requests with 401/400, and attaches the resolved
   :class:`Principal` to ``request.state.principal`` when valid.
3. :func:`require_scope` — a FastAPI dependency factory that
   pre-emptively 403s when the authenticated principal is missing any
   of the required scopes. Used on the router side via
   ``dependencies=[Depends(require_scope("incidents:trigger"))]``.
4. :func:`seed_tokens_from_settings` — converts the env-driven
   ``API_AUTH_TOKEN`` into a default admin principal at startup.

**Auth is auto-disabled when the registry is empty.** That is the
continuation of the pre-P2.1 behaviour — every existing unit/E2E test
that doesn't supply an ``API_AUTH_TOKEN`` keeps working. Tests that
want to verify auth behavior explicitly provision tokens into the
registry via :func:`TokenRegistry.add`.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from backend.shared.principal import Principal, hash_token

logger = logging.getLogger(__name__)

# Scopes granted to a Cloudflare-Access-authenticated dashboard user.
# A session can do everything an operator can within its OWN tenant;
# cross-tenant access is prevented by account_id scoping, not scope.
_CF_SESSION_SCOPES = frozenset({
    "incidents:read", "incidents:trigger", "watcher:control",
})


# ---------------------------------------------------------------------------
# Token registry
# ---------------------------------------------------------------------------


@dataclass
class TokenRegistry:
    """In-memory bearer-token registry.

    Tokens are never stored in plain text; we keep only the
    ``hash_token(raw)`` as the key and the associated
    :class:`Principal`. Revoked hashes are kept in a separate set so
    audit logs can still reference a revoked principal by id.
    """

    _tokens: dict[str, Principal] = field(default_factory=dict)
    _revoked: set[str] = field(default_factory=set)
    _lock: Lock = field(default_factory=Lock)

    # -- Mutation ---------------------------------------------------------
    def add(self, raw_token: str, principal: Principal) -> None:
        """Register ``raw_token`` as authorized to act as ``principal``."""
        key = hash_token(raw_token)
        with self._lock:
            self._tokens[key] = principal
            self._revoked.discard(key)

    def revoke(self, raw_token: str) -> bool:
        """Revoke ``raw_token``. Returns True if it was previously active."""
        key = hash_token(raw_token)
        with self._lock:
            existed = key in self._tokens
            if existed:
                self._revoked.add(key)
            return existed

    def revoke_by_hash(self, token_hash: str) -> bool:
        """Revoke by already-computed hash (used by admin UIs)."""
        with self._lock:
            existed = token_hash in self._tokens
            if existed:
                self._revoked.add(token_hash)
            return existed

    def clear(self) -> None:
        """Wipe the registry — used by tests to reset state."""
        with self._lock:
            self._tokens.clear()
            self._revoked.clear()

    # -- Inspection -------------------------------------------------------
    def is_empty(self) -> bool:
        """True iff no tokens are registered — auth is disabled when this is True."""
        with self._lock:
            return not self._tokens

    def is_revoked(self, raw_token: str) -> bool:
        key = hash_token(raw_token)
        with self._lock:
            return key in self._revoked

    def resolve(self, raw_token: str) -> Principal | None:
        """Return the Principal for ``raw_token``, or None on miss/revoked."""
        key = hash_token(raw_token)
        with self._lock:
            if key in self._revoked:
                return None
            principal: Principal | None = self._tokens.get(key)
            return principal


# ---------------------------------------------------------------------------
# Startup helpers
# ---------------------------------------------------------------------------


def seed_tokens_from_settings(settings: Any, registry: TokenRegistry) -> None:
    """Convert the legacy ``API_AUTH_TOKEN`` env knob into a default admin.

    P2.1 keeps things simple: if the operator configured
    ``API_AUTH_TOKEN`` we treat that one token as an admin principal
    (``scopes={"*"}``). Proper multi-token management (DB rows, CLI
    mint / revoke, rotation) lands in P4.2 —
    :func:`hydrate_registry_from_repo` below.
    """
    token = (getattr(settings, "api_auth_token", None) or "").strip()
    if not token:
        return
    principal = Principal(
        id=hash_token(token)[:12],
        name="env-admin",
        role="admin",
        scopes=frozenset({"*"}),
    )
    registry.add(token, principal)
    logger.info("Auth: seeded admin token from API_AUTH_TOKEN (id=%s)", principal.id)


async def hydrate_registry_from_repo(registry: TokenRegistry, token_repo: Any) -> int:
    """P4.2: rebuild the in-memory registry from persisted ``api_tokens`` rows.

    The in-memory :class:`TokenRegistry` is keyed by the raw token (so
    the middleware hot path stays lock-free and synchronous). At
    startup the raw tokens are not available — we only have their
    hashes from the DB. We therefore register each stored row under
    its already-hashed key by calling an internal ``_add_hashed``
    path.

    Already-revoked rows are added to the registry's revocation set so
    a previously-leaked token that somehow reaches the middleware is
    still rejected, even though it's no longer a live principal.

    Returns the number of active principals hydrated.
    """
    active = 0
    stored_tokens = await token_repo.list_all(include_revoked=True)
    for stored in stored_tokens:
        principal = Principal(
            id=stored.id,
            name=stored.name,
            role=stored.role,
            scopes=frozenset(stored.scopes),
        )
        with registry._lock:
            if stored.is_revoked:
                # Record the hash as revoked WITHOUT adding it back to the
                # active map. If the raw token ever shows up on the wire,
                # _get_registry(request).is_revoked() will still see it.
                registry._revoked.add(stored.token_hash)
            else:
                registry._tokens[stored.token_hash] = principal
                registry._revoked.discard(stored.token_hash)
                active += 1
    logger.info(
        "Auth: hydrated %d active principals from token repo (%d total stored)",
        active, len(stored_tokens),
    )
    return active


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

# Paths that are always served without authentication. Liveness probe
# and OpenAPI / Swagger UI need to work before or without tokens.
_OPEN_PATHS: frozenset[str] = frozenset({
    "/api/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/",
    # SaaS: signup + login must be reachable before a session token
    # exists. ``/api/ingest`` authenticates with its own
    # ``X-Ingest-Token`` header (resolved inside the handler), not the
    # dashboard bearer — so it is exempt from the bearer middleware too.
    "/api/auth/signup",
    "/api/auth/login",
    # Tells the SPA which auth mode is active (password vs Cloudflare
    # Access) before the user is authenticated — must be open.
    "/api/auth/config",
    "/api/ingest",
})


def _extract_bearer(request: Request) -> tuple[str | None, str | None]:
    """Parse the ``Authorization`` header.

    Returns
    -------
    (raw_token, error_reason)
        * When a valid ``Bearer <token>`` is present: ``(token, None)``.
        * When nothing was sent: ``(None, None)`` — caller decides if
          that's a 401 or an anonymous request.
        * When something looked like auth but was malformed (wrong
          scheme, token in query string): ``(None, reason)``.
    """
    # Reject tokens carried in query strings — SEC-04. They leak into
    # access logs and server-side metrics. Do this check before the
    # header parse so even callers mixing header+query get a clean 400.
    if "token" in request.query_params:
        return None, "token_in_query"

    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth_header:
        return None, None

    parts = auth_header.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None, "bad_scheme"
    raw = parts[1].strip()
    if not raw:
        return None, "empty_token"
    return raw, None


class AuthMiddleware(BaseHTTPMiddleware):
    """Enforce bearer-token auth on every API call (when enabled).

    Behaviour matrix:

    +-----------------+-----------------------+-----------------------+
    |                 | registry is empty     | registry has tokens   |
    +=================+=======================+=======================+
    | no header       | pass-through          | 401                   |
    +-----------------+-----------------------+-----------------------+
    | bad header      | 400                   | 400                   |
    +-----------------+-----------------------+-----------------------+
    | token in query  | 400 (SEC-04)          | 400 (SEC-04)          |
    +-----------------+-----------------------+-----------------------+
    | unknown token   | pass-through (dev)    | 401                   |
    +-----------------+-----------------------+-----------------------+
    | revoked token   | 401                   | 401                   |
    +-----------------+-----------------------+-----------------------+
    | valid token     | attach principal      | attach principal      |
    +-----------------+-----------------------+-----------------------+

    When auth is disabled (empty registry) unrecognized or absent
    tokens are ignored so the existing test suite — which never sends
    a token — keeps passing.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Always allow liveness + docs endpoints.
        if request.url.path in _OPEN_PATHS:
            return await call_next(request)

        # ── Cloudflare Access (SaaS auth) ──────────────────────────────
        # When a CF Access verifier is configured, prefer the
        # cryptographically-verified ``Cf-Access-Jwt-Assertion`` header.
        # A valid JWT auto-provisions/loads the tenant account and
        # attaches its Principal — the dashboard never sends a bearer.
        cf_principal = await self._resolve_cf_access(request)
        if cf_principal is not None:
            request.state.principal = cf_principal
            return await call_next(request)

        registry = _get_registry(request)
        auth_required = registry is not None and not registry.is_empty()

        raw_token, err = _extract_bearer(request)

        # Malformed headers are always a 400 — even in dev mode — so
        # clients don't silently ship broken auth integrations.
        if err == "token_in_query":
            return _json_error(400, "Token must be supplied via Authorization header, not query string")
        if err in {"bad_scheme", "empty_token"}:
            return _json_error(400, "Invalid Authorization header; expected 'Bearer <token>'")

        if raw_token is None:
            if auth_required:
                return _json_error(401, "Authentication required")
            # Dev mode: no token sent, no tokens registered — anonymous.
            return await call_next(request)

        principal = registry.resolve(raw_token) if registry else None
        if principal is None:
            # Registered but revoked, or unknown-but-auth-required.
            if registry and registry.is_revoked(raw_token):
                return _json_error(401, "Token has been revoked")
            if auth_required:
                return _json_error(401, "Invalid bearer token")
            # Dev mode: unknown token, but no tokens registered. The
            # operator almost certainly meant "no auth" so we let this
            # through as anonymous. Still log it so it's not silent.
            logger.debug(
                "Auth disabled (no tokens registered) — ignoring bearer token on %s",
                request.url.path,
            )
            return await call_next(request)

        request.state.principal = principal
        return await call_next(request)

    @staticmethod
    async def _resolve_cf_access(request: Request) -> Principal | None:
        """Verify the Cloudflare Access JWT and map it to a Principal.

        Returns ``None`` when Access auth isn't configured or the header
        is absent/invalid — the caller then falls through to the
        bearer-token path. Auto-provisions an ``accounts`` row on the
        first time we see a given verified email and caches the
        resulting Principal on the container so subsequent requests
        skip the DB.
        """
        from backend.api.cf_access import CF_ACCESS_JWT_HEADER

        try:
            container = request.app.state.container
        except AttributeError:
            return None
        if container is None:
            return None
        verifier = getattr(container, "cf_verifier", None)
        if verifier is None or not getattr(verifier, "enabled", False):
            return None

        token = request.headers.get(CF_ACCESS_JWT_HEADER)
        if not token:
            return None
        claims = verifier.verify(token)
        if claims is None:
            return None
        email = verifier.email_from_claims(claims)
        if not email:
            return None

        cache = getattr(container, "cf_principal_cache", None)
        if cache is not None and email in cache:
            cached: Principal = cache[email]
            return cached

        # Auto-provision (or load) the account for this verified email.
        account_repo = getattr(container, "account_repo", None)
        account_id: str | None = None
        if account_repo is not None:
            try:
                account = await account_repo.get_or_create_sso(email)
                account_id = account.id
            except Exception:  # pragma: no cover — defensive
                logger.exception("CF Access: account provisioning failed for %s", email)

        principal = Principal(
            id=account_id or hash_token(email)[:12],
            name=email,
            role="account",
            scopes=_CF_SESSION_SCOPES,
            account_id=account_id,
        )
        if cache is not None:
            cache[email] = principal
        return principal


def _get_registry(request: Request) -> TokenRegistry | None:
    """Pull the TokenRegistry off the app container, if attached."""
    try:
        container = request.app.state.container
    except AttributeError:
        return None
    return getattr(container, "auth_tokens", None)


def _json_error(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": detail})


# ---------------------------------------------------------------------------
# Scope gate (FastAPI Depends)
# ---------------------------------------------------------------------------


def require_scope(*scopes: str) -> Callable[[Request], Awaitable[Principal | None]]:
    """Return a FastAPI dependency that enforces all ``scopes``.

    * 401 when auth is enabled but no principal resolved.
    * 403 when the principal is missing any of the required scopes.
    * When auth is disabled (empty registry) the dependency is a no-op
      so dev mode keeps working without ceremony.
    """

    async def _enforce(request: Request) -> Principal | None:
        registry = _get_registry(request)
        auth_required = registry is not None and not registry.is_empty()

        principal: Principal | None = getattr(request.state, "principal", None)

        if principal is None:
            if not auth_required:
                return None  # Dev mode, no enforcement.
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )

        missing = [s for s in scopes if not principal.has_scope(s)]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope(s): {','.join(missing)}",
            )
        return principal

    return _enforce


__all__ = [
    "AuthMiddleware",
    "TokenRegistry",
    "hydrate_registry_from_repo",
    "require_scope",
    "seed_tokens_from_settings",
]
