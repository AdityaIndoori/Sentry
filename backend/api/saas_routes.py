"""
SaaS API surface — signup / login / ingestion / onboarding.

This module is additive: it defines a FastAPI ``APIRouter`` that is
mounted by :func:`backend.api.app.create_app`. Every handler reads its
dependencies (account repo, ingestion-token repo, the in-memory
``TokenRegistry``, and the orchestrator) off the request's
:class:`~backend.shared.container.ServiceContainer`, so the wiring stays
consistent with the rest of the app and tests can attach a container.

Endpoints
---------
* ``POST /api/auth/signup``  — create an account, return a session token.
* ``POST /api/auth/login``   — verify credentials, return a session token.
* ``GET  /api/auth/me``      — who am I (requires bearer).
* ``GET  /api/ingest-tokens``        — list this tenant's ingestion tokens.
* ``POST /api/ingest-tokens``        — mint a new ingestion token (returns raw once).
* ``DELETE /api/ingest-tokens/{id}`` — revoke an ingestion token.
* ``POST /api/ingest``       — remote log-line ingestion (``X-Ingest-Token`` auth).

Session tokens reuse the existing opaque-bearer machinery: a successful
signup/login mints a random token, registers it in the live
``TokenRegistry`` (and persists a row via ``token_repo`` so it survives a
restart) bound to a :class:`Principal` whose ``account_id`` is the new
account. From that point on the existing ``AuthMiddleware`` +
``require_scope`` rails enforce auth and carry the tenant identity.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel

from backend.shared.accounts import validate_signup
from backend.shared.models import LogEvent
from backend.shared.principal import Principal, generate_token, hash_token

logger = logging.getLogger(__name__)

router = APIRouter()

# Scopes granted to a logged-in dashboard session. A session can do
# everything an operator can within its own tenant; cross-tenant access
# is prevented by account_id filtering, not by scope.
_SESSION_SCOPES = ("incidents:read", "incidents:trigger", "watcher:control")


# ─── Request / response bodies ──────────────────────────────────────────────


class SignupRequest(BaseModel):
    email: str
    password: str
    display_name: str = ""


class LoginRequest(BaseModel):
    email: str
    password: str


class MintIngestTokenRequest(BaseModel):
    service_name: str = ""


class IngestRequest(BaseModel):
    """One or more log lines shipped by a customer's service.

    ``source`` labels the log file/stream; ``lines`` is the batch of raw
    log lines. Each line is screened against the watcher's error
    patterns server-side, so a customer can fire-hose us their whole log
    and only matching lines spin up an incident.
    """

    source: str = "remote"
    lines: list[str] = []
    # Single-line convenience (``message`` or ``lines`` — either works).
    message: str | None = None


# ─── Helpers ────────────────────────────────────────────────────────────────


def _container(request: Request) -> Any:
    return getattr(request.app.state, "container", None)


def _account_repo(request: Request) -> Any:
    c = _container(request)
    repo = getattr(c, "account_repo", None) if c else None
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Accounts are not enabled on this deployment (no database configured).",
        )
    return repo


def _ingest_repo(request: Request) -> Any:
    c = _container(request)
    repo = getattr(c, "ingestion_token_repo", None) if c else None
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ingestion is not enabled on this deployment (no database configured).",
        )
    return repo


async def _mint_session(request: Request, account: Any) -> str:
    """Mint + register a session bearer token bound to ``account``.

    Returns the raw token (shown to the SPA, stored client-side). The
    token is registered in the live registry and best-effort persisted.
    """
    raw = "sess_" + generate_token(32)
    principal = Principal(
        id=account.id,
        name=account.email,
        role="account",
        scopes=frozenset(_SESSION_SCOPES),
        account_id=account.id,
    )
    container = _container(request)
    registry = getattr(container, "auth_tokens", None) if container else None
    if registry is not None:
        registry.add(raw, principal)
    # Best-effort durable persistence so the session survives a restart.
    token_repo = getattr(container, "token_repo", None) if container else None
    if token_repo is not None:
        try:
            await token_repo.create(
                token_id=hash_token(raw)[:12],
                token_hash=hash_token(raw),
                name=f"session:{account.email}",
                role="account",
                scopes=list(_SESSION_SCOPES),
            )
        except Exception:  # pragma: no cover — non-fatal
            logger.exception("session token persistence failed for %s", account.id)
    return raw


def _require_principal(request: Request) -> Principal:
    principal: Principal | None = getattr(request.state, "principal", None)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return principal


# ─── Auth ─────────────────────────────────────────────────────────────────


@router.post("/api/auth/signup")
async def signup(body: SignupRequest, request: Request) -> dict[str, Any]:
    err = validate_signup(body.email, body.password)
    if err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err)
    repo = _account_repo(request)
    try:
        account = await repo.create(
            email=body.email,
            password=body.password,
            display_name=body.display_name,
        )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with that email already exists.",
        ) from None
    token = await _mint_session(request, account)
    return {
        "token": token,
        "account": {"id": account.id, "email": account.email,
                    "display_name": account.display_name},
    }


@router.post("/api/auth/login")
async def login(body: LoginRequest, request: Request) -> dict[str, Any]:
    repo = _account_repo(request)
    account = await repo.authenticate(body.email, body.password)
    if account is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    token = await _mint_session(request, account)
    return {
        "token": token,
        "account": {"id": account.id, "email": account.email,
                    "display_name": account.display_name},
    }


@router.get("/api/auth/config")
async def auth_config(request: Request) -> dict[str, Any]:
    """Tell the SPA which auth mode is active.

    When Cloudflare Access is enabled the frontend skips its own
    password screen entirely (Access already authenticated the browser
    at the edge) and uses ``logout_url`` for sign-out.
    """
    container = _container(request)
    verifier = getattr(container, "cf_verifier", None) if container else None
    cf_enabled = bool(verifier is not None and getattr(verifier, "enabled", False))
    return {
        "mode": "cloudflare_access" if cf_enabled else "password",
        "cf_access_enabled": cf_enabled,
        "logout_url": getattr(verifier, "logout_url", "") if cf_enabled else "",
    }


@router.get("/api/auth/me")
async def me(request: Request) -> dict[str, Any]:
    principal = _require_principal(request)
    return {
        "id": principal.id,
        "name": principal.name,
        "role": principal.role,
        "account_id": principal.account_id,
        "scopes": sorted(principal.scopes),
    }


# ─── Ingestion-token management (onboarding) ────────────────────────────────


@router.get("/api/ingest-tokens")
async def list_ingest_tokens(request: Request) -> dict[str, Any]:
    principal = _require_principal(request)
    if not principal.account_id:
        raise HTTPException(status_code=403, detail="No account context.")
    repo = _ingest_repo(request)
    tokens = await repo.list_for_account(principal.account_id)
    return {
        "tokens": [
            {
                "id": t.id,
                "service_name": t.service_name,
                "created_at": t.created_at.isoformat(),
                "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
            }
            for t in tokens
        ]
    }


@router.post("/api/ingest-tokens")
async def mint_ingest_token(body: MintIngestTokenRequest, request: Request) -> dict[str, Any]:
    principal = _require_principal(request)
    if not principal.account_id:
        raise HTTPException(status_code=403, detail="No account context.")
    repo = _ingest_repo(request)
    minted = await repo.mint(account_id=principal.account_id, service_name=body.service_name)
    return {
        "id": minted.id,
        "service_name": minted.service_name,
        # The raw token is returned exactly once — the SPA must surface it
        # to the user immediately; it cannot be recovered later.
        "token": minted.raw_token,
    }


@router.delete("/api/ingest-tokens/{token_id}")
async def revoke_ingest_token(token_id: str, request: Request) -> dict[str, Any]:
    principal = _require_principal(request)
    if not principal.account_id:
        raise HTTPException(status_code=403, detail="No account context.")
    repo = _ingest_repo(request)
    revoked = await repo.revoke(account_id=principal.account_id, token_id=token_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="Token not found.")
    return {"revoked": True, "id": token_id}


# ─── Remote log ingestion ───────────────────────────────────────────────────


@router.post("/api/ingest")
async def ingest(
    body: IngestRequest,
    request: Request,
    x_ingest_token: str | None = Header(default=None, alias="X-Ingest-Token"),
) -> dict[str, Any]:
    """Accept log lines from a customer's service and feed matching ones
    into that tenant's incident pipeline.

    Auth is via the ``X-Ingest-Token`` header (NOT the dashboard bearer)
    so a customer drops exactly one secret into their log shipper. The
    token resolves to an ``account_id`` and every spawned incident is
    tagged with it.
    """
    if not x_ingest_token:
        raise HTTPException(status_code=401, detail="Missing X-Ingest-Token header.")
    repo = _ingest_repo(request)
    resolved = await repo.resolve(x_ingest_token)
    if resolved is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked ingestion token.")

    container = _container(request)
    orchestrator = getattr(container, "orchestrator", None) if container else None
    config = getattr(container, "config", None) if container else None
    if orchestrator is None:
        raise HTTPException(status_code=503, detail="Orchestrator unavailable.")

    lines = list(body.lines)
    if body.message:
        lines.append(body.message)
    if not lines:
        return {"accepted": 0, "matched": 0}

    patterns = _error_patterns(config)
    source = resolved.service_name or body.source or "remote"

    matched = 0
    for line in lines:
        pattern = _first_match(line, patterns)
        if pattern is None:
            continue
        matched += 1
        event = LogEvent(
            source_file=source,
            line_content=line,
            matched_pattern=pattern,
            account_id=resolved.account_id,
        )
        # Fire the pipeline. handle_event already dedups/suppresses, so a
        # log storm of identical lines collapses to one incident.
        try:
            await orchestrator.handle_event(event)
        except Exception:  # pragma: no cover — never fail the ingest call
            logger.exception("ingest: handle_event failed for account=%s", resolved.account_id)

    return {"accepted": len(lines), "matched": matched}


# ─── Pattern matching helpers ───────────────────────────────────────────────


def _error_patterns(config: Any) -> list[str]:
    """Return the regex error patterns to screen ingested lines against.

    Falls back to a sensible default set when no watcher config is wired
    (e.g. the orchestrator-only test harness).
    """
    try:
        patterns = list(config.watcher.error_patterns)
        if patterns:
            return patterns
    except Exception:
        pass
    return [r"(?i)error", r"(?i)critical", r"(?i)fatal", r"(?i)exception",
            r"\b50[0-9]\b"]


def _first_match(line: str, patterns: list[str]) -> str | None:
    for pat in patterns:
        try:
            if re.search(pat, line):
                return pat
        except re.error:  # pragma: no cover — bad operator pattern
            continue
    return None


__all__ = ["router"]
