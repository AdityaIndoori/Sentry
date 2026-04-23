"""
P4.6 regression tests — REST token-management endpoints.

Covers the three admin-only routes added in P4.6:

* ``POST   /api/tokens``         — mint a new token (returns the raw
                                     value exactly once).
* ``GET    /api/tokens``         — list persisted tokens (metadata
                                     only, raw never returned).
* ``DELETE /api/tokens/{id}``   — revoke and remove from the
                                     in-memory registry.

Each test builds a fresh FastAPI app via ``create_app(container=...)``
with an isolated SQLite-backed ``TokenRepository`` and a seeded admin
token carrying the ``admin:tokens`` scope. That's enough to exercise
the real middleware / scope-gate / repo wiring without standing up
Postgres or docker-compose.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from backend.api.app import create_app
from backend.api.auth import TokenRegistry
from backend.persistence.repositories.token_repo import TokenRepository
from backend.persistence.session import build_database
from backend.shared.container import ServiceContainer
from backend.shared.principal import Principal, generate_token, hash_token


@pytest.fixture
async def token_stack(tmp_path):
    """Build a minimal ``(app, client, admin_raw_token, token_repo)`` harness.

    Uses a per-test SQLite file so tests don't leak state. Only the
    subset of the ServiceContainer that the token routes need is
    wired up — everything else (orchestrator, watcher, etc.) is
    deliberately ``None`` so the token endpoints are the only thing
    the app can serve.
    """
    db_path = tmp_path / "tokens_api.db"
    db = build_database(f"sqlite+aiosqlite:///{db_path}")
    await db.create_all()
    token_repo = TokenRepository(db)

    # Admin token: admin:tokens + * (so we can also hit incidents:read
    # endpoints if a test later wants to).
    admin_raw = generate_token()
    admin_hash = hash_token(admin_raw)
    await token_repo.create(
        token_id=admin_hash[:12],
        token_hash=admin_hash,
        name="e2e-admin",
        role="admin",
        scopes=["admin:tokens", "*"],
    )

    registry = TokenRegistry()
    admin_principal = Principal(
        id=admin_hash[:12],
        name="e2e-admin",
        role="admin",
        scopes=frozenset({"admin:tokens", "*"}),
    )
    registry.add(admin_raw, admin_principal)

    # Container stub — only token-related fields matter for these tests.
    container = ServiceContainer(
        auth_tokens=registry,
        token_repo=token_repo,
    )

    app = create_app(container=container)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, admin_raw, token_repo, registry

    await db.engine.dispose()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ─────────────────────────────────────────────────────────────────────
# POST /api/tokens
# ─────────────────────────────────────────────────────────────────────


class TestCreateToken:
    @pytest.mark.asyncio
    async def test_create_returns_raw_token_once(self, token_stack):
        client, admin, _repo, _reg = token_stack
        resp = await client.post(
            "/api/tokens",
            json={"name": "grafana", "role": "read_only", "scopes": ["incidents:read"]},
            headers=_auth(admin),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["name"] == "grafana"
        assert body["role"] == "read_only"
        assert body["scopes"] == ["incidents:read"]
        # The raw token is present exactly once and is 40+ chars (token_urlsafe(32)).
        raw = body["raw_token"]
        assert isinstance(raw, str) and len(raw) >= 40
        # The stored id matches the first 12 chars of the hash.
        assert body["id"] == hash_token(raw)[:12]

    @pytest.mark.asyncio
    async def test_create_requires_admin_tokens_scope(self, tmp_path):
        """A token without admin:tokens gets 403 — even if it has '*'
        on read scopes. The explicit scope gate is the point."""
        db = build_database(f"sqlite+aiosqlite:///{tmp_path / 'scoped.db'}")
        await db.create_all()
        repo = TokenRepository(db)

        # operator principal: can read incidents, CANNOT manage tokens.
        op_raw = generate_token()
        op_hash = hash_token(op_raw)
        await repo.create(
            token_id=op_hash[:12], token_hash=op_hash,
            name="operator", role="operator",
            scopes=["incidents:read", "incidents:trigger"],
        )
        registry = TokenRegistry()
        registry.add(op_raw, Principal(
            id=op_hash[:12], name="operator", role="operator",
            scopes=frozenset({"incidents:read", "incidents:trigger"}),
        ))

        container = ServiceContainer(auth_tokens=registry, token_repo=repo)
        app = create_app(container=container)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/tokens",
                json={"name": "nope", "scopes": ["*"]},
                headers=_auth(op_raw),
            )
        await db.engine.dispose()
        assert resp.status_code == 403
        assert "admin:tokens" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_rejects_empty_scopes(self, token_stack):
        client, admin, *_ = token_stack
        resp = await client.post(
            "/api/tokens",
            json={"name": "empty", "scopes": []},
            headers=_auth(admin),
        )
        assert resp.status_code == 400
        assert "scopes" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_rejects_invalid_role(self, token_stack):
        client, admin, *_ = token_stack
        resp = await client.post(
            "/api/tokens",
            json={"name": "bad", "role": "root", "scopes": ["*"]},
            headers=_auth(admin),
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_create_unauthenticated_rejected(self, token_stack):
        client, *_ = token_stack
        resp = await client.post(
            "/api/tokens",
            json={"name": "x", "scopes": ["*"]},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_created_token_works_on_read_endpoint(self, token_stack):
        """Smoke test: a newly-minted token with ``*`` scope can hit
        a read-protected endpoint immediately — no restart required."""
        client, admin, _repo, _reg = token_stack
        mint = await client.post(
            "/api/tokens",
            json={"name": "bot", "role": "admin", "scopes": ["*"]},
            headers=_auth(admin),
        )
        assert mint.status_code == 201
        new_raw = mint.json()["raw_token"]

        # Hit the token list with the new token — should work because
        # its scopes contain "*".
        resp = await client.get("/api/tokens", headers=_auth(new_raw))
        assert resp.status_code == 200


# ─────────────────────────────────────────────────────────────────────
# GET /api/tokens
# ─────────────────────────────────────────────────────────────────────


class TestListTokens:
    @pytest.mark.asyncio
    async def test_list_returns_metadata_only(self, token_stack):
        client, admin, _repo, _reg = token_stack
        # Mint a second token so the listing has more than just the seed.
        await client.post(
            "/api/tokens",
            json={"name": "t2", "scopes": ["incidents:read"]},
            headers=_auth(admin),
        )
        resp = await client.get("/api/tokens", headers=_auth(admin))
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] >= 2
        # Raw tokens must NEVER appear in list output.
        for t in body["tokens"]:
            assert "raw_token" not in t
            assert "token" not in t
            assert "token_hash" not in t
            assert set(t.keys()) >= {
                "id", "name", "role", "scopes",
                "created_at", "revoked_at", "is_revoked",
            }

    @pytest.mark.asyncio
    async def test_list_hides_revoked_by_default(self, token_stack):
        client, admin, _repo, _reg = token_stack
        mint = await client.post(
            "/api/tokens",
            json={"name": "will-be-revoked", "scopes": ["*"]},
            headers=_auth(admin),
        )
        new_id = mint.json()["id"]
        # Revoke.
        r = await client.delete(f"/api/tokens/{new_id}", headers=_auth(admin))
        assert r.status_code == 200

        # Default list excludes revoked.
        default = await client.get("/api/tokens", headers=_auth(admin))
        assert new_id not in {t["id"] for t in default.json()["tokens"]}

        # ?include_revoked=true includes them.
        all_tokens = await client.get(
            "/api/tokens?include_revoked=true", headers=_auth(admin),
        )
        assert new_id in {t["id"] for t in all_tokens.json()["tokens"]}


# ─────────────────────────────────────────────────────────────────────
# DELETE /api/tokens/{id}
# ─────────────────────────────────────────────────────────────────────


class TestRevokeToken:
    @pytest.mark.asyncio
    async def test_revoke_success_and_registry_reject(self, token_stack):
        client, admin, _repo, _registry = token_stack
        mint = await client.post(
            "/api/tokens",
            json={"name": "short-lived", "scopes": ["*"]},
            headers=_auth(admin),
        )
        new_id = mint.json()["id"]
        new_raw = mint.json()["raw_token"]

        # Sanity: the new token works before revocation.
        pre = await client.get("/api/tokens", headers=_auth(new_raw))
        assert pre.status_code == 200

        # Revoke.
        r = await client.delete(f"/api/tokens/{new_id}", headers=_auth(admin))
        assert r.status_code == 200
        body = r.json()
        assert body == {"id": new_id, "revoked": True, "already_revoked": False}

        # The in-memory registry immediately rejects the raw token.
        post = await client.get("/api/tokens", headers=_auth(new_raw))
        assert post.status_code == 401

    @pytest.mark.asyncio
    async def test_revoke_unknown_id_404(self, token_stack):
        client, admin, *_ = token_stack
        r = await client.delete(
            "/api/tokens/deadbeef0000", headers=_auth(admin),
        )
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_revoke_is_idempotent(self, token_stack):
        client, admin, *_ = token_stack
        mint = await client.post(
            "/api/tokens",
            json={"name": "idempotent", "scopes": ["*"]},
            headers=_auth(admin),
        )
        tid = mint.json()["id"]

        r1 = await client.delete(f"/api/tokens/{tid}", headers=_auth(admin))
        r2 = await client.delete(f"/api/tokens/{tid}", headers=_auth(admin))
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json()["already_revoked"] is False
        assert r2.json()["already_revoked"] is True

    @pytest.mark.asyncio
    async def test_revoke_requires_admin_tokens_scope(self, tmp_path):
        """Same scope-gating as create — operator cannot revoke."""
        db = build_database(f"sqlite+aiosqlite:///{tmp_path / 'scoped.db'}")
        await db.create_all()
        repo = TokenRepository(db)

        # Seed one admin token (so we can mint a victim), one operator.
        admin_raw = generate_token()
        admin_hash = hash_token(admin_raw)
        await repo.create(
            token_id=admin_hash[:12], token_hash=admin_hash,
            name="admin", role="admin", scopes=["admin:tokens"],
        )
        op_raw = generate_token()
        op_hash = hash_token(op_raw)
        await repo.create(
            token_id=op_hash[:12], token_hash=op_hash,
            name="op", role="operator", scopes=["incidents:read"],
        )

        registry = TokenRegistry()
        registry.add(admin_raw, Principal(
            id=admin_hash[:12], name="admin", role="admin",
            scopes=frozenset({"admin:tokens"}),
        ))
        registry.add(op_raw, Principal(
            id=op_hash[:12], name="op", role="operator",
            scopes=frozenset({"incidents:read"}),
        ))

        container = ServiceContainer(auth_tokens=registry, token_repo=repo)
        app = create_app(container=container)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Operator cannot revoke the admin's token.
            resp = await client.delete(
                f"/api/tokens/{admin_hash[:12]}", headers=_auth(op_raw),
            )
        await db.engine.dispose()
        assert resp.status_code == 403
