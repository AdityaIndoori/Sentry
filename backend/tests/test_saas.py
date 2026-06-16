"""
Tests for the SaaS multi-tenant foundation:

1. Password primitives — hash/verify round-trip, bad-input safety.
2. Account repository — create / duplicate-email / authenticate.
3. Ingestion-token repository — mint / resolve / revoke / tenant isolation.
4. API flow (TestClient) — signup → login → /me → mint ingest token →
   ingest a matching log line → incident is created and tagged with the
   right account_id; cross-tenant token revocation is rejected.

Everything runs against an in-memory SQLite database so no external
services are required.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from backend.persistence.repositories.account_repo import AccountRepository
from backend.persistence.repositories.ingestion_token_repo import (
    IngestionTokenRepository,
)
from backend.persistence.session import build_database
from backend.shared.accounts import (
    hash_password,
    is_valid_email,
    normalize_email,
    validate_signup,
    verify_password,
)

# ═══════════════════════════════════════════════════════════════
# 1. Password primitives
# ═══════════════════════════════════════════════════════════════


class TestPasswordPrimitives:
    def test_hash_verify_roundtrip(self):
        h = hash_password("correct horse battery staple", iterations=1000)
        assert verify_password("correct horse battery staple", h) is True
        assert verify_password("wrong password", h) is False

    def test_hash_is_salted(self):
        a = hash_password("same", iterations=1000)
        b = hash_password("same", iterations=1000)
        assert a != b  # different salt → different hash
        assert verify_password("same", a)
        assert verify_password("same", b)

    def test_verify_never_raises_on_garbage(self):
        assert verify_password("x", "") is False
        assert verify_password("x", "not$a$valid$hash$extra") is False
        assert verify_password("x", "bcrypt$12$abc$def") is False

    def test_email_validation_and_normalization(self):
        assert is_valid_email("Foo@Bar.com")
        assert not is_valid_email("nope")
        assert not is_valid_email("a@b")
        assert normalize_email("  Foo@BAR.com ") == "foo@bar.com"

    def test_validate_signup(self):
        assert validate_signup("a@b.com", "longenough") is None
        assert validate_signup("bad", "longenough") is not None
        assert validate_signup("a@b.com", "short") is not None


# ═══════════════════════════════════════════════════════════════
# Async DB fixture
# ═══════════════════════════════════════════════════════════════


@pytest.fixture
async def db():
    database = build_database("sqlite+aiosqlite:///:memory:")
    await database.create_all()
    try:
        yield database
    finally:
        await database.dispose()


# ═══════════════════════════════════════════════════════════════
# 2. Account repository
# ═══════════════════════════════════════════════════════════════


class TestAccountRepository:
    @pytest.mark.asyncio
    async def test_create_and_get(self, db):
        repo = AccountRepository(db)
        acct = await repo.create(email="User@Example.com", password="hunter2pass")
        assert acct.id.startswith("acct_")
        assert acct.email == "user@example.com"  # normalized
        fetched = await repo.get(acct.id)
        assert fetched is not None
        assert fetched.email == "user@example.com"

    @pytest.mark.asyncio
    async def test_duplicate_email_rejected(self, db):
        repo = AccountRepository(db)
        await repo.create(email="dup@example.com", password="password123")
        with pytest.raises(ValueError):
            await repo.create(email="DUP@example.com", password="password123")

    @pytest.mark.asyncio
    async def test_authenticate(self, db):
        repo = AccountRepository(db)
        await repo.create(email="auth@example.com", password="correctpass")
        assert await repo.authenticate("auth@example.com", "correctpass") is not None
        assert await repo.authenticate("auth@example.com", "wrongpass") is None
        assert await repo.authenticate("missing@example.com", "whatever") is None


# ═══════════════════════════════════════════════════════════════
# 3. Ingestion-token repository
# ═══════════════════════════════════════════════════════════════


class TestIngestionTokenRepository:
    @pytest.mark.asyncio
    async def test_mint_resolve(self, db):
        repo = IngestionTokenRepository(db)
        minted = await repo.mint(account_id="acct_a", service_name="prod-api")
        assert minted.raw_token.startswith("sing_")
        resolved = await repo.resolve(minted.raw_token)
        assert resolved is not None
        assert resolved.account_id == "acct_a"
        assert resolved.service_name == "prod-api"

    @pytest.mark.asyncio
    async def test_revoke_then_resolve_fails(self, db):
        repo = IngestionTokenRepository(db)
        minted = await repo.mint(account_id="acct_a")
        assert await repo.revoke(account_id="acct_a", token_id=minted.id) is True
        assert await repo.resolve(minted.raw_token) is None

    @pytest.mark.asyncio
    async def test_cross_tenant_revoke_rejected(self, db):
        repo = IngestionTokenRepository(db)
        minted = await repo.mint(account_id="acct_a")
        # acct_b must not be able to revoke acct_a's token.
        assert await repo.revoke(account_id="acct_b", token_id=minted.id) is False
        assert await repo.resolve(minted.raw_token) is not None

    @pytest.mark.asyncio
    async def test_list_scoped_to_account(self, db):
        repo = IngestionTokenRepository(db)
        await repo.mint(account_id="acct_a", service_name="s1")
        await repo.mint(account_id="acct_a", service_name="s2")
        await repo.mint(account_id="acct_b", service_name="s3")
        a_tokens = await repo.list_for_account("acct_a")
        b_tokens = await repo.list_for_account("acct_b")
        assert len(a_tokens) == 2
        assert len(b_tokens) == 1


# ═══════════════════════════════════════════════════════════════
# 4. End-to-end API flow via TestClient
# ═══════════════════════════════════════════════════════════════


def _build_saas_app():
    """Build a real app + container against in-memory sqlite, with a
    scripted orchestrator so we can assert on ingested events."""
    import tempfile

    from backend.api.app import create_app
    from backend.shared.factory import build_container
    from backend.shared.settings import Settings

    tmp = tempfile.mkdtemp(prefix="sentry-saas-")
    settings = Settings(
        memory_file_path=f"{tmp}/mem.json",
        audit_log_path=f"{tmp}/audit.jsonl",
        watch_paths=(),
    )
    container = build_container(settings, llm_override=AsyncMock())

    # Replace the orchestrator with a capture double so we can assert
    # which events were ingested without running the LLM pipeline.
    captured: list = []

    class _CaptureOrch:
        async def handle_event(self, event):
            captured.append(event)
            return None

    container.orchestrator = _CaptureOrch()
    app = create_app(container)
    return app, container, captured


class TestSaaSApiFlow:
    def test_signup_login_ingest_flow(self):
        from fastapi.testclient import TestClient

        app, container, captured = _build_saas_app()
        try:
            with TestClient(app) as client:
                # 1) Signup → token
                r = client.post("/api/auth/signup", json={
                    "email": "founder@startup.com", "password": "supersecret",
                })
                assert r.status_code == 200, r.text
                token = r.json()["token"]
                account_id = r.json()["account"]["id"]
                assert token.startswith("sess_")

                auth = {"Authorization": f"Bearer {token}"}

                # 2) /me reflects the account
                me = client.get("/api/auth/me", headers=auth)
                assert me.status_code == 200
                assert me.json()["account_id"] == account_id

                # 3) Mint an ingestion token
                mint = client.post("/api/ingest-tokens", headers=auth,
                                   json={"service_name": "prod-api"})
                assert mint.status_code == 200, mint.text
                ingest_token = mint.json()["token"]
                assert ingest_token.startswith("sing_")

                # 4) Ingest a matching + a non-matching line
                ing = client.post("/api/ingest",
                                  headers={"X-Ingest-Token": ingest_token},
                                  json={"lines": [
                                      "ERROR: redis connection refused",
                                      "INFO: all good here",
                                  ]})
                assert ing.status_code == 200, ing.text
                assert ing.json()["accepted"] == 2
                assert ing.json()["matched"] == 1

                # The matching line became an event tagged with the tenant.
                assert len(captured) == 1
                assert captured[0].account_id == account_id
                assert "redis" in captured[0].line_content

                # 5) Duplicate signup → 409
                dup = client.post("/api/auth/signup", json={
                    "email": "founder@startup.com", "password": "supersecret",
                })
                assert dup.status_code == 409

                # 6) Bad ingest token → 401
                bad = client.post("/api/ingest",
                                 headers={"X-Ingest-Token": "sing_nope"},
                                 json={"lines": ["ERROR boom"]})
                assert bad.status_code == 401
        finally:
            asyncio.get_event_loop().run_until_complete(container.shutdown()) \
                if not asyncio.get_event_loop().is_running() else None

    def test_login_wrong_password_rejected(self):
        from fastapi.testclient import TestClient

        app, container, _ = _build_saas_app()
        try:
            with TestClient(app) as client:
                client.post("/api/auth/signup", json={
                    "email": "user@co.com", "password": "rightpassword",
                })
                ok = client.post("/api/auth/login", json={
                    "email": "user@co.com", "password": "rightpassword",
                })
                assert ok.status_code == 200
                bad = client.post("/api/auth/login", json={
                    "email": "user@co.com", "password": "wrongpassword",
                })
                assert bad.status_code == 401
        finally:
            asyncio.get_event_loop().run_until_complete(container.shutdown()) \
                if not asyncio.get_event_loop().is_running() else None
