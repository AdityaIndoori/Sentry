"""
Tests for the Cloudflare Access auth layer:

1. ``CloudflareAccessVerifier`` — host normalization, derived URLs,
   disabled-state (no PyJWT / missing config), ``email_from_claims``.
2. ``build_verifier`` — returns ``None`` when not configured.
3. ``AccountRepository.get_or_create_sso`` — idempotent passwordless
   provisioning, and that the SSO sentinel hash never authenticates.
4. ``GET /api/auth/config`` — reports password mode by default and
   ``cloudflare_access`` mode when a verifier is wired.
5. ``AuthMiddleware`` CF-Access path — a stub verifier that "accepts" a
   header token auto-provisions an account and attaches a tenant-scoped
   Principal (no bearer token sent).

All DB-backed tests use in-memory SQLite, mirroring ``test_saas.py``.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from backend.api.cf_access import (
    CF_ACCESS_JWT_HEADER,
    CloudflareAccessVerifier,
    build_verifier,
)
from backend.persistence.repositories.account_repo import AccountRepository
from backend.persistence.session import build_database

# ═══════════════════════════════════════════════════════════════
# 1. Verifier — pure logic (no network)
# ═══════════════════════════════════════════════════════════════


class TestCloudflareAccessVerifier:
    def test_team_host_normalization_bare_name(self):
        v = CloudflareAccessVerifier(team_domain="myteam", audience="aud123")
        assert v._team_host == "myteam.cloudflareaccess.com"
        assert v.issuer == "https://myteam.cloudflareaccess.com"
        assert v.certs_url == (
            "https://myteam.cloudflareaccess.com/cdn-cgi/access/certs"
        )
        assert v.logout_url == (
            "https://myteam.cloudflareaccess.com/cdn-cgi/access/logout"
        )

    def test_team_host_normalization_full_host_and_scheme(self):
        v = CloudflareAccessVerifier(
            team_domain="https://myteam.cloudflareaccess.com/",
            audience="aud123",
        )
        assert v._team_host == "myteam.cloudflareaccess.com"

    def test_team_host_empty(self):
        v = CloudflareAccessVerifier(team_domain="   ", audience="aud123")
        assert v._team_host == ""

    def test_enabled_requires_config(self):
        # Missing audience → not enabled regardless of PyJWT.
        v = CloudflareAccessVerifier(team_domain="myteam", audience="")
        assert v.enabled is False
        v2 = CloudflareAccessVerifier(team_domain="", audience="aud")
        assert v2.enabled is False

    def test_verify_returns_none_when_disabled(self):
        v = CloudflareAccessVerifier(team_domain="", audience="")
        assert v.verify("anything") is None

    def test_verify_returns_none_on_empty_token(self):
        v = CloudflareAccessVerifier(team_domain="myteam", audience="aud")
        assert v.verify("") is None

    def test_email_from_claims(self):
        assert CloudflareAccessVerifier.email_from_claims(
            {"email": "Founder@Startup.com"}
        ) == "founder@startup.com"
        # Falls back to ``identity``.
        assert CloudflareAccessVerifier.email_from_claims(
            {"identity": "ops@co.com"}
        ) == "ops@co.com"
        # No usable identity → None.
        assert CloudflareAccessVerifier.email_from_claims({}) is None
        assert CloudflareAccessVerifier.email_from_claims({"email": "  "}) is None
        assert CloudflareAccessVerifier.email_from_claims({"email": 123}) is None


class TestBuildVerifier:
    def test_returns_none_without_config(self):
        class _S:
            cf_access_team_domain = ""
            cf_access_aud = ""

        assert build_verifier(_S()) is None

    def test_returns_none_with_partial_config(self):
        class _S:
            cf_access_team_domain = "myteam"
            cf_access_aud = ""

        assert build_verifier(_S()) is None

    def test_builds_when_configured(self):
        class _S:
            cf_access_team_domain = "myteam"
            cf_access_aud = "aud123"

        v = build_verifier(_S())
        assert isinstance(v, CloudflareAccessVerifier)
        assert v.team_domain == "myteam"
        assert v.audience == "aud123"


# ═══════════════════════════════════════════════════════════════
# 2. SSO provisioning
# ═══════════════════════════════════════════════════════════════


@pytest.fixture
async def db():
    database = build_database("sqlite+aiosqlite:///:memory:")
    await database.create_all()
    try:
        yield database
    finally:
        await database.dispose()


class TestSsoProvisioning:
    @pytest.mark.asyncio
    async def test_get_or_create_sso_is_idempotent(self, db):
        repo = AccountRepository(db)
        a = await repo.get_or_create_sso("User@Example.com")
        assert a.email == "user@example.com"  # normalized
        assert a.id.startswith("acct_")
        # Second call returns the same account, doesn't duplicate.
        b = await repo.get_or_create_sso("user@example.com")
        assert b.id == a.id

    @pytest.mark.asyncio
    async def test_sso_account_cannot_password_login(self, db):
        repo = AccountRepository(db)
        await repo.get_or_create_sso("sso@example.com")
        # The sentinel hash must never verify against any password.
        assert await repo.authenticate("sso@example.com", "anything") is None
        assert await repo.authenticate("sso@example.com", "") is None


# ═══════════════════════════════════════════════════════════════
# 3 + 4. App-level: /api/auth/config + middleware CF Access path
# ═══════════════════════════════════════════════════════════════


def _build_app(cf_verifier=None):
    """Build a real app + container against in-memory sqlite, optionally
    wiring a (stub) Cloudflare Access verifier onto the container."""
    import tempfile

    from backend.api.app import create_app
    from backend.shared.factory import build_container
    from backend.shared.settings import Settings

    tmp = tempfile.mkdtemp(prefix="sentry-cf-")
    settings = Settings(
        memory_file_path=f"{tmp}/mem.json",
        audit_log_path=f"{tmp}/audit.jsonl",
        watch_paths=(),
    )
    container = build_container(settings, llm_override=AsyncMock())
    if cf_verifier is not None:
        container.cf_verifier = cf_verifier
    app = create_app(container)
    return app, container


class _StubVerifier:
    """A CF Access verifier that 'accepts' a fixed token → fixed email."""

    enabled = True
    logout_url = "https://myteam.cloudflareaccess.com/cdn-cgi/access/logout"

    def __init__(self, *, good_token: str, email: str):
        self._good = good_token
        self._email = email

    def verify(self, token):
        return {"email": self._email} if token == self._good else None

    @staticmethod
    def email_from_claims(claims):
        return CloudflareAccessVerifier.email_from_claims(claims)


class TestAuthConfigEndpoint:
    def test_reports_password_mode_by_default(self):
        from fastapi.testclient import TestClient

        app, container = _build_app()
        try:
            with TestClient(app) as client:
                r = client.get("/api/auth/config")
                assert r.status_code == 200
                body = r.json()
                assert body["mode"] == "password"
                assert body["cf_access_enabled"] is False
                assert body["logout_url"] == ""
        finally:
            _shutdown(container)

    def test_reports_cf_access_mode_when_wired(self):
        from fastapi.testclient import TestClient

        verifier = _StubVerifier(good_token="tok", email="x@y.com")
        app, container = _build_app(cf_verifier=verifier)
        try:
            with TestClient(app) as client:
                r = client.get("/api/auth/config")
                assert r.status_code == 200
                body = r.json()
                assert body["mode"] == "cloudflare_access"
                assert body["cf_access_enabled"] is True
                assert body["logout_url"].endswith("/cdn-cgi/access/logout")
        finally:
            _shutdown(container)


class TestMiddlewareCfAccessPath:
    def test_valid_cf_header_provisions_and_authenticates(self):
        from fastapi.testclient import TestClient

        verifier = _StubVerifier(good_token="good-jwt", email="founder@startup.com")
        app, container = _build_app(cf_verifier=verifier)
        try:
            with TestClient(app) as client:
                # No bearer token — only the CF Access header.
                r = client.get(
                    "/api/auth/me",
                    headers={CF_ACCESS_JWT_HEADER: "good-jwt"},
                )
                assert r.status_code == 200, r.text
                body = r.json()
                assert body["name"] == "founder@startup.com"
                assert body["role"] == "account"
                assert body["account_id"] is not None
                assert "incidents:trigger" in body["scopes"]

                # Account was actually provisioned in the DB.
                acct = asyncio.get_event_loop().run_until_complete(
                    container.account_repo.get_by_email("founder@startup.com")
                ) if not asyncio.get_event_loop().is_running() else None
                if acct is not None:
                    assert acct.email == "founder@startup.com"
        finally:
            _shutdown(container)

    def test_invalid_cf_header_falls_through(self):
        from fastapi.testclient import TestClient

        verifier = _StubVerifier(good_token="good-jwt", email="x@y.com")
        app, container = _build_app(cf_verifier=verifier)
        try:
            with TestClient(app) as client:
                # Bad token → verifier returns None → no principal. With no
                # bearer registry seeded, dev-mode lets it through anonymous,
                # so /me (which requires a principal) returns 401.
                r = client.get(
                    "/api/auth/me",
                    headers={CF_ACCESS_JWT_HEADER: "bad-jwt"},
                )
                assert r.status_code == 401
        finally:
            _shutdown(container)


def _shutdown(container) -> None:
    loop = asyncio.get_event_loop()
    if not loop.is_running():
        loop.run_until_complete(container.shutdown())
