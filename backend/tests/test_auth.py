"""
P2.1 unit tests — Principal + TokenRegistry + require_scope.

The full HTTP surface is exercised in
``backend/tests/e2e/test_security.py::test_sec01*..test_sec04*``.
This file focuses on the pure building blocks so a regression in
`hash_token`, the registry, or the scope helper is caught close to
where it happens.
"""

from __future__ import annotations

import pytest

from backend.api.auth import (
    TokenRegistry,
    require_scope,
    seed_tokens_from_settings,
)
from backend.shared.principal import (
    Principal,
    constant_time_equals,
    generate_token,
    hash_token,
)


# ---------------------------------------------------------------------------
# Principal
# ---------------------------------------------------------------------------


class TestPrincipal:
    def test_has_scope_matches_on_exact_scope(self):
        p = Principal(
            id="x", name="n", role="operator",
            scopes=frozenset({"incidents:read"}),
        )
        assert p.has_scope("incidents:read") is True
        assert p.has_scope("incidents:trigger") is False

    def test_has_scope_wildcard_admin(self):
        p = Principal(
            id="x", name="n", role="admin", scopes=frozenset({"*"}),
        )
        assert p.has_scope("incidents:read") is True
        assert p.has_scope("watcher:control") is True
        assert p.has_scope("anything:at:all") is True

    def test_has_scope_multiple(self):
        p = Principal(
            id="x", name="n", role="operator",
            scopes=frozenset({"incidents:read", "incidents:trigger"}),
        )
        assert p.has_scope("incidents:read") is True
        assert p.has_scope("incidents:trigger") is True
        assert p.has_scope("watcher:control") is False


class TestHashToken:
    def test_hash_is_deterministic(self):
        assert hash_token("abc") == hash_token("abc")

    def test_hash_differs_for_different_inputs(self):
        assert hash_token("abc") != hash_token("abd")

    def test_hash_is_full_sha256_hex(self):
        h = hash_token("x")
        assert len(h) == 64  # hex chars from sha256
        assert all(c in "0123456789abcdef" for c in h)


class TestConstantTimeEquals:
    def test_equal_strings(self):
        assert constant_time_equals("abc", "abc") is True

    def test_unequal_strings(self):
        assert constant_time_equals("abc", "abd") is False

    def test_different_lengths_still_safe(self):
        assert constant_time_equals("abc", "abcd") is False


class TestGenerateToken:
    def test_tokens_are_unique(self):
        a = generate_token()
        b = generate_token()
        assert a != b

    def test_default_length_is_reasonable(self):
        t = generate_token()
        # token_urlsafe(32) -> ~43 chars. Must be non-trivial.
        assert len(t) >= 32


# ---------------------------------------------------------------------------
# TokenRegistry
# ---------------------------------------------------------------------------


@pytest.fixture
def principal_admin():
    return Principal(
        id="admin-1", name="admin-1", role="admin", scopes=frozenset({"*"}),
    )


@pytest.fixture
def principal_reader():
    return Principal(
        id="read-1", name="read-1", role="read_only",
        scopes=frozenset({"incidents:read"}),
    )


class TestTokenRegistry:
    def test_empty_registry_is_empty(self):
        r = TokenRegistry()
        assert r.is_empty() is True
        assert r.resolve("anything") is None

    def test_add_then_resolve(self, principal_admin):
        r = TokenRegistry()
        r.add("tok", principal_admin)
        assert r.is_empty() is False
        assert r.resolve("tok") == principal_admin

    def test_resolve_wrong_token_returns_none(self, principal_admin):
        r = TokenRegistry()
        r.add("tok", principal_admin)
        assert r.resolve("WRONG") is None

    def test_revoke_existing_token(self, principal_admin):
        r = TokenRegistry()
        r.add("tok", principal_admin)
        assert r.revoke("tok") is True
        assert r.is_revoked("tok") is True
        assert r.resolve("tok") is None

    def test_revoke_unknown_token_returns_false(self):
        r = TokenRegistry()
        assert r.revoke("never-registered") is False

    def test_clear_wipes_state(self, principal_admin):
        r = TokenRegistry()
        r.add("tok", principal_admin)
        r.revoke("tok")
        r.clear()
        assert r.is_empty() is True
        assert r.is_revoked("tok") is False

    def test_re_add_after_revoke_reactivates(self, principal_admin):
        """Re-adding a token clears any prior revocation for that hash."""
        r = TokenRegistry()
        r.add("tok", principal_admin)
        r.revoke("tok")
        assert r.is_revoked("tok") is True
        r.add("tok", principal_admin)  # re-issue
        assert r.is_revoked("tok") is False
        assert r.resolve("tok") == principal_admin

    def test_tokens_are_not_stored_in_plaintext(self, principal_admin):
        """Internal dict keys must be hashes, never raw tokens."""
        r = TokenRegistry()
        r.add("super-secret-token", principal_admin)
        # Peek at internal state — keys must be the hash, not the raw token.
        assert "super-secret-token" not in r._tokens
        assert hash_token("super-secret-token") in r._tokens


class TestSeedTokensFromSettings:
    def test_empty_settings_adds_nothing(self):
        r = TokenRegistry()

        class _S:
            api_auth_token = ""

        seed_tokens_from_settings(_S(), r)
        assert r.is_empty() is True

    def test_present_token_seeds_admin_principal(self):
        r = TokenRegistry()

        class _S:
            api_auth_token = "dev-seed-token"

        seed_tokens_from_settings(_S(), r)
        p = r.resolve("dev-seed-token")
        assert p is not None
        assert p.role == "admin"
        assert "*" in p.scopes

    def test_missing_attr_is_tolerated(self):
        """seed_tokens_from_settings must not crash on a settings object
        without an ``api_auth_token`` attribute (belt-and-braces)."""
        r = TokenRegistry()

        class _S:
            pass  # no api_auth_token at all

        seed_tokens_from_settings(_S(), r)
        assert r.is_empty() is True


# ---------------------------------------------------------------------------
# require_scope (FastAPI dependency)
# ---------------------------------------------------------------------------


class _FakeRequestState:
    """Mimics the attribute-set shape of Starlette's request.state."""

    def __init__(self, principal: Principal | None = None):
        if principal is not None:
            self.principal = principal


class _FakeRequest:
    """Minimal shape required by ``require_scope`` — only ``.app.state.container``
    (for the registry) and ``.state`` (for the principal)."""

    def __init__(self, registry: TokenRegistry | None, principal: Principal | None = None):
        class _Container:
            pass

        c = _Container()
        c.auth_tokens = registry

        class _App:
            pass

        app = _App()

        class _AppState:
            pass

        app.state = _AppState()
        app.state.container = c if registry is not None else None

        self.app = app
        self.state = _FakeRequestState(principal)


class TestRequireScope:
    @pytest.mark.asyncio
    async def test_no_principal_dev_mode_is_pass_through(self):
        """Empty registry + no principal -> dep returns None (dev mode)."""
        dep = require_scope("incidents:read")
        req = _FakeRequest(registry=TokenRegistry(), principal=None)
        result = await dep(req)
        assert result is None

    @pytest.mark.asyncio
    async def test_no_principal_when_auth_enabled_is_401(self, principal_admin):
        from fastapi import HTTPException

        registry = TokenRegistry()
        registry.add("tok", principal_admin)
        dep = require_scope("incidents:read")
        req = _FakeRequest(registry=registry, principal=None)
        with pytest.raises(HTTPException) as exc:
            await dep(req)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_scope_is_403(self, principal_reader):
        from fastapi import HTTPException

        registry = TokenRegistry()
        registry.add("tok", principal_reader)
        dep = require_scope("incidents:trigger")
        req = _FakeRequest(registry=registry, principal=principal_reader)
        with pytest.raises(HTTPException) as exc:
            await dep(req)
        assert exc.value.status_code == 403
        assert "scope" in str(exc.value.detail).lower()

    @pytest.mark.asyncio
    async def test_matching_scope_returns_principal(self, principal_reader):
        registry = TokenRegistry()
        registry.add("tok", principal_reader)
        dep = require_scope("incidents:read")
        req = _FakeRequest(registry=registry, principal=principal_reader)
        result = await dep(req)
        assert result == principal_reader

    @pytest.mark.asyncio
    async def test_wildcard_admin_passes_any_scope(self, principal_admin):
        registry = TokenRegistry()
        registry.add("tok", principal_admin)
        dep = require_scope("anything:absurd")
        req = _FakeRequest(registry=registry, principal=principal_admin)
        result = await dep(req)
        assert result == principal_admin

    @pytest.mark.asyncio
    async def test_multiple_scopes_all_must_match(self, principal_reader):
        from fastapi import HTTPException

        registry = TokenRegistry()
        registry.add("tok", principal_reader)
        # principal_reader has only "incidents:read"
        dep = require_scope("incidents:read", "incidents:trigger")
        req = _FakeRequest(registry=registry, principal=principal_reader)
        with pytest.raises(HTTPException) as exc:
            await dep(req)
        assert exc.value.status_code == 403
