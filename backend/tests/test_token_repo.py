"""
P4.2 regression tests — ``TokenRepository`` + ``hydrate_registry_from_repo``
+ the three operator CLIs.

Everything runs against a per-test SQLite file through the real
``build_database`` factory, so these tests exercise the same
SQLAlchemy 2.0 path the production stack hits with Postgres. The
``sentry`` raw-token value is never persisted — the DB only ever sees
its SHA-256 hash.
"""

from __future__ import annotations

import asyncio
from io import StringIO
from unittest.mock import patch

import pytest

from backend.api.auth import TokenRegistry, hydrate_registry_from_repo
from backend.persistence.repositories.token_repo import StoredToken, TokenRepository
from backend.persistence.session import build_database
from backend.shared.principal import generate_token, hash_token


@pytest.fixture
async def repo(tmp_path):
    """Fresh SQLite-backed TokenRepository per test."""
    db_path = tmp_path / "tokens.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    db = build_database(url)
    await db.create_all()
    yield TokenRepository(db)
    await db.engine.dispose()


class TestTokenRepositoryCreate:
    @pytest.mark.asyncio
    async def test_create_persists_row(self, repo: TokenRepository):
        raw = generate_token()
        token_hash = hash_token(raw)
        stored = await repo.create(
            token_id=token_hash[:12],
            token_hash=token_hash,
            name="t1",
            role="admin",
            scopes=["*"],
        )
        assert stored.id == token_hash[:12]
        assert stored.token_hash == token_hash
        assert stored.name == "t1"
        assert stored.role == "admin"
        assert stored.scopes == ("*",)
        assert stored.revoked_at is None

    @pytest.mark.asyncio
    async def test_create_never_stores_raw(self, repo: TokenRepository, tmp_path):
        """Regression: the raw token must never appear in the DB file."""
        raw = generate_token()
        token_hash = hash_token(raw)
        await repo.create(
            token_id=token_hash[:12],
            token_hash=token_hash,
            name="t1",
            role="admin",
            scopes=["*"],
        )
        # Drop the engine so the WAL flushes.
        # (The raw bytes of ``raw`` should not appear in the sqlite file.)
        # We can't grep the file without engine dispose; the fixture
        # does that on teardown but we need it now. Open the file
        # directly after letting aiosqlite checkpoint.
        await asyncio.sleep(0.05)
        db_file = next(tmp_path.glob("*.db"))
        content = db_file.read_bytes()
        assert raw.encode() not in content, "Raw token must never be persisted"

    @pytest.mark.asyncio
    async def test_create_duplicate_id_raises(self, repo: TokenRepository):
        """Inserting a second row with the same id surfaces an error."""
        raw1 = generate_token()
        h1 = hash_token(raw1)
        await repo.create(
            token_id=h1[:12], token_hash=h1,
            name="a", role="admin", scopes=["*"],
        )
        # Same id, different hash.
        with pytest.raises(Exception):
            await repo.create(
                token_id=h1[:12], token_hash="x" * 64,
                name="b", role="admin", scopes=["*"],
            )


class TestTokenRepositoryReads:
    @pytest.mark.asyncio
    async def test_get_by_id_and_hash(self, repo: TokenRepository):
        raw = generate_token()
        h = hash_token(raw)
        await repo.create(
            token_id=h[:12], token_hash=h,
            name="t", role="admin", scopes=["*"],
        )
        by_id = await repo.get(h[:12])
        by_hash = await repo.get_by_hash(h)
        assert by_id is not None and by_hash is not None
        assert by_id.id == by_hash.id == h[:12]

    @pytest.mark.asyncio
    async def test_list_filters_revoked(self, repo: TokenRepository):
        raw1, raw2 = generate_token(), generate_token()
        h1, h2 = hash_token(raw1), hash_token(raw2)
        await repo.create(
            token_id=h1[:12], token_hash=h1,
            name="alive", role="admin", scopes=["*"],
        )
        await repo.create(
            token_id=h2[:12], token_hash=h2,
            name="dead", role="operator", scopes=["incidents:read"],
        )
        await repo.revoke(h2[:12])

        active = await repo.list_all()
        everything = await repo.list_all(include_revoked=True)
        assert {t.name for t in active} == {"alive"}
        assert {t.name for t in everything} == {"alive", "dead"}


class TestTokenRepositoryRevoke:
    @pytest.mark.asyncio
    async def test_revoke_sets_timestamp(self, repo: TokenRepository):
        raw = generate_token()
        h = hash_token(raw)
        await repo.create(
            token_id=h[:12], token_hash=h,
            name="t", role="admin", scopes=["*"],
        )
        assert await repo.revoke(h[:12]) is True
        stored = await repo.get(h[:12])
        assert stored is not None
        assert stored.is_revoked is True

    @pytest.mark.asyncio
    async def test_revoke_is_idempotent(self, repo: TokenRepository):
        raw = generate_token()
        h = hash_token(raw)
        await repo.create(
            token_id=h[:12], token_hash=h,
            name="t", role="admin", scopes=["*"],
        )
        assert await repo.revoke(h[:12]) is True
        assert await repo.revoke(h[:12]) is False  # already revoked

    @pytest.mark.asyncio
    async def test_revoke_unknown_id_returns_false(self, repo: TokenRepository):
        assert await repo.revoke("deadbeef0000") is False


class TestHydrateRegistryFromRepo:
    @pytest.mark.asyncio
    async def test_hydrates_active_tokens_as_principals(self, repo: TokenRepository):
        raw = generate_token()
        h = hash_token(raw)
        await repo.create(
            token_id=h[:12], token_hash=h,
            name="grafana", role="read_only",
            scopes=["incidents:read"],
        )

        registry = TokenRegistry()
        count = await hydrate_registry_from_repo(registry, repo)
        assert count == 1
        # The raw token should now resolve to the hydrated principal.
        principal = registry.resolve(raw)
        assert principal is not None
        assert principal.name == "grafana"
        assert principal.role == "read_only"
        assert principal.scopes == frozenset({"incidents:read"})

    @pytest.mark.asyncio
    async def test_revoked_rows_go_to_revocation_set(self, repo: TokenRepository):
        raw = generate_token()
        h = hash_token(raw)
        await repo.create(
            token_id=h[:12], token_hash=h,
            name="t", role="admin", scopes=["*"],
        )
        await repo.revoke(h[:12])

        registry = TokenRegistry()
        count = await hydrate_registry_from_repo(registry, repo)
        assert count == 0
        # Revoked hash must be rejected even though it was persisted.
        assert registry.resolve(raw) is None
        assert registry.is_revoked(raw) is True

    @pytest.mark.asyncio
    async def test_empty_repo_leaves_registry_empty(self, repo: TokenRepository):
        registry = TokenRegistry()
        count = await hydrate_registry_from_repo(registry, repo)
        assert count == 0
        assert registry.is_empty() is True


class TestCreateAdminTokenCLI:
    """Integration test: the CLI hits a real SQLite DB and prints a raw token."""

    def test_cli_creates_token_and_prints_it(self, tmp_path, monkeypatch, capsys):
        from backend.scripts import create_admin_token as cli

        # Force the CLI to use our tmp sqlite file by mocking get_settings.
        from backend.shared.settings import Settings
        import dataclasses

        db_url = f"sqlite+aiosqlite:///{tmp_path / 'cli.db'}"
        fake_settings = dataclasses.replace(
            Settings(),
            database_url=db_url,
            memory_file_path=str(tmp_path / "mem.json"),
        )

        def _fake_get_settings():
            return fake_settings

        monkeypatch.setattr(cli, "get_settings", _fake_get_settings)

        rc = cli.main(["--name", "testing", "--role", "admin", "--scopes", "*"])
        assert rc == 0

        captured = capsys.readouterr()
        # Raw token on stdout — URL-safe token_urlsafe(32) is ~43 chars.
        raw = captured.out.strip()
        assert len(raw) >= 40
        # Created banner on stderr.
        assert "API token created" in captured.err

        # DB row exists.
        async def _verify():
            db = build_database(db_url)
            repo = TokenRepository(db)
            try:
                tokens = await repo.list_all()
            finally:
                await db.engine.dispose()
            assert len(tokens) == 1
            assert tokens[0].name == "testing"
            assert tokens[0].role == "admin"
            # The stored hash matches SHA-256 of the printed raw token.
            assert tokens[0].token_hash == hash_token(raw)

        asyncio.run(_verify())

    def test_cli_rejects_empty_scopes(self):
        from backend.scripts import create_admin_token as cli
        with pytest.raises(SystemExit):
            cli.main(["--name", "x", "--scopes", "  "])


class TestRevokeTokenCLI:
    def test_cli_revokes_existing_token(self, tmp_path, monkeypatch, capsys):
        from backend.scripts import create_admin_token as create_cli
        from backend.scripts import revoke_token as revoke_cli
        from backend.shared.settings import Settings
        import dataclasses

        db_url = f"sqlite+aiosqlite:///{tmp_path / 'cli.db'}"
        fake = dataclasses.replace(
            Settings(),
            database_url=db_url,
            memory_file_path=str(tmp_path / "mem.json"),
        )
        monkeypatch.setattr(create_cli, "get_settings", lambda: fake)
        monkeypatch.setattr(revoke_cli, "get_settings", lambda: fake)

        assert create_cli.main(["--name", "t", "--scopes", "*"]) == 0
        raw = capsys.readouterr().out.strip()
        token_id = hash_token(raw)[:12]

        assert revoke_cli.main([token_id]) == 0
        out = capsys.readouterr().err
        assert "revoked" in out

        # A second revoke returns non-zero.
        assert revoke_cli.main([token_id]) == 1


class TestListTokensCLI:
    def test_cli_lists_active_only(self, tmp_path, monkeypatch, capsys):
        from backend.scripts import create_admin_token as create_cli
        from backend.scripts import list_tokens as list_cli
        from backend.scripts import revoke_token as revoke_cli
        from backend.shared.settings import Settings
        import dataclasses

        db_url = f"sqlite+aiosqlite:///{tmp_path / 'cli.db'}"
        fake = dataclasses.replace(
            Settings(),
            database_url=db_url,
            memory_file_path=str(tmp_path / "mem.json"),
        )
        for mod in (create_cli, list_cli, revoke_cli):
            monkeypatch.setattr(mod, "get_settings", lambda _f=fake: _f)

        # Create two tokens, revoke one.
        create_cli.main(["--name", "alive", "--scopes", "*"])
        raw_alive = capsys.readouterr().out.strip()
        create_cli.main(["--name", "dead", "--scopes", "incidents:read"])
        raw_dead = capsys.readouterr().out.strip()
        revoke_cli.main([hash_token(raw_dead)[:12]])
        capsys.readouterr()  # drain

        # Active list shows only 'alive'.
        list_cli.main([])
        out = capsys.readouterr().out
        assert "alive" in out
        assert "dead" not in out

        # --all shows both.
        list_cli.main(["--all"])
        out = capsys.readouterr().out
        assert "alive" in out
        assert "dead" in out
        assert "revoked" in out
