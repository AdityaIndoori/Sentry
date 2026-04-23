"""
P2.2 unit tests — ISecretsProvider + EnvSecrets + FileSecrets +
build_secrets_provider factory.

SopsSecrets and VaultSecrets have runtime-only dependencies (the sops
CLI, the hvac package + a Vault server) so only their "missing prereq"
error paths are covered here; the happy-path flows for those backends
are exercised in integration tests in a later phase.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend.shared.secrets import (
    EnvSecrets,
    FileSecrets,
    ISecretsProvider,
    SopsSecrets,
    VaultSecrets,
    build_secrets_provider,
)

# ---------------------------------------------------------------------------
# ISecretsProvider.require
# ---------------------------------------------------------------------------


class _FixedProvider(ISecretsProvider):
    def __init__(self, values):
        self._v = values

    def get(self, name):
        return self._v.get(name)


class TestRequire:
    def test_require_returns_value_when_present(self):
        p = _FixedProvider({"x": "hello"})
        assert p.require("x") == "hello"

    def test_require_raises_on_missing(self):
        p = _FixedProvider({})
        with pytest.raises(KeyError, match="Secret 'x' not found"):
            p.require("x")

    def test_require_raises_on_empty_string(self):
        """Empty strings are treated as missing — a common footgun."""
        p = _FixedProvider({"x": ""})
        with pytest.raises(KeyError):
            p.require("x")


# ---------------------------------------------------------------------------
# EnvSecrets
# ---------------------------------------------------------------------------


class TestEnvSecrets:
    def test_prefixed_lookup_preferred(self, monkeypatch):
        monkeypatch.setenv("SECRET_ANTHROPIC_API_KEY", "prefixed-value")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "legacy-value")
        p = EnvSecrets()
        assert p.get("anthropic_api_key") == "prefixed-value"

    def test_legacy_fallback(self, monkeypatch):
        monkeypatch.delenv("SECRET_ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "legacy-value")
        p = EnvSecrets()
        assert p.get("anthropic_api_key") == "legacy-value"

    def test_missing_returns_none(self, monkeypatch):
        monkeypatch.delenv("SECRET_NOPE", raising=False)
        monkeypatch.delenv("NOPE", raising=False)
        p = EnvSecrets()
        assert p.get("nope") is None

    def test_case_insensitive_input_normalized_to_upper(self, monkeypatch):
        """Caller passes logical name in any case; env var is upper-case."""
        monkeypatch.setenv("SECRET_MIXED_CASE", "v")
        p = EnvSecrets()
        assert p.get("Mixed_Case") == "v"
        assert p.get("mixed_case") == "v"

    def test_custom_prefix(self, monkeypatch):
        monkeypatch.setenv("APP_KEY", "x")
        p = EnvSecrets(prefix="APP_")
        assert p.get("key") == "x"


# ---------------------------------------------------------------------------
# FileSecrets
# ---------------------------------------------------------------------------


class TestFileSecrets:
    def test_reads_file_contents(self, tmp_path):
        (tmp_path / "api_auth_token").write_text("tok-123\n", encoding="utf-8")
        p = FileSecrets(root=str(tmp_path))
        assert p.get("api_auth_token") == "tok-123"

    def test_strips_only_trailing_newlines(self, tmp_path):
        """Internal whitespace / leading space is preserved — the operator
        may legitimately have a token that starts/ends with a space."""
        (tmp_path / "k").write_text("  value  \n", encoding="utf-8")
        p = FileSecrets(root=str(tmp_path))
        assert p.get("k") == "  value  "

    def test_missing_file_returns_none(self, tmp_path):
        p = FileSecrets(root=str(tmp_path))
        assert p.get("absent") is None


# ---------------------------------------------------------------------------
# SopsSecrets error paths (happy path runs in integration tests only).
# ---------------------------------------------------------------------------


class TestSopsSecrets:
    def test_missing_binary_raises_runtime_error(self, monkeypatch):
        """When `sops` isn't on PATH, constructing SopsSecrets must fail
        loudly — never silently fall through to an empty config."""
        monkeypatch.setattr(
            "backend.shared.secrets.shutil.which", lambda _cmd: None,
        )
        with pytest.raises(RuntimeError, match="sops.*not found on PATH"):
            SopsSecrets(sops_file="/tmp/secrets.yaml")

    def test_parse_structured_json(self):
        from backend.shared.secrets import _parse_structured

        data = _parse_structured('{"a": "1", "b": {"c": "2"}}')
        assert data == {"a": "1", "b": {"c": "2"}}

    def test_dotted_lookup_with_injected_payload(self):
        """Exercise the lookup logic by bypassing _decrypt."""
        # Build an instance with a pre-populated payload.
        p = SopsSecrets.__new__(SopsSecrets)
        p._file = "fake.yaml"  # type: ignore[attr-defined]
        p._payload = {  # type: ignore[attr-defined]
            "anthropic": {"api_key": "sk-xyz"},
            "db": {"url": "postgres://..."},
            "retries": 3,
        }
        assert p.get("anthropic.api_key") == "sk-xyz"
        assert p.get("db.url") == "postgres://..."
        assert p.get("retries") == "3"  # coerced to str
        assert p.get("anthropic.missing") is None
        assert p.get("nope") is None
        # Partial-path that hits a scalar returns None.
        assert p.get("retries.sub") is None


# ---------------------------------------------------------------------------
# VaultSecrets error path
# ---------------------------------------------------------------------------


class TestVaultSecrets:
    def test_missing_credentials_raises(self, monkeypatch):
        """No token and no role_id/secret_id → RuntimeError, not a half-
        configured client that silently returns None on every lookup."""
        try:
            import hvac  # noqa: F401
        except ImportError:
            pytest.skip("hvac not installed — vault test not applicable")
        with pytest.raises(RuntimeError, match="no credentials"):
            VaultSecrets(addr="http://127.0.0.1:8200")


# ---------------------------------------------------------------------------
# build_secrets_provider factory
# ---------------------------------------------------------------------------


class TestFactory:
    def test_default_is_env_provider(self):
        s = SimpleNamespace(secrets_backend=None)
        p = build_secrets_provider(s)
        assert isinstance(p, EnvSecrets)

    def test_env_explicit(self):
        s = SimpleNamespace(secrets_backend="env")
        assert isinstance(build_secrets_provider(s), EnvSecrets)

    def test_unknown_backend_falls_back_to_env(self, caplog):
        s = SimpleNamespace(secrets_backend="martian")
        with caplog.at_level("WARNING"):
            p = build_secrets_provider(s)
        assert isinstance(p, EnvSecrets)
        assert any("Unknown SECRETS_BACKEND" in r.message for r in caplog.records)

    def test_file_backend_respects_override_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FILE_SECRETS_ROOT", str(tmp_path))
        (tmp_path / "k").write_text("v\n", encoding="utf-8")
        s = SimpleNamespace(secrets_backend="file")
        p = build_secrets_provider(s)
        assert isinstance(p, FileSecrets)
        assert p.get("k") == "v"

    def test_sops_backend_requires_file(self):
        s = SimpleNamespace(secrets_backend="sops", secrets_sops_file=None)
        with pytest.raises(RuntimeError, match="secrets_sops_file"):
            build_secrets_provider(s)

    def test_vault_backend_requires_addr(self):
        s = SimpleNamespace(secrets_backend="vault", secrets_vault_addr=None)
        with pytest.raises(RuntimeError, match="secrets_vault_addr"):
            build_secrets_provider(s)

    def test_case_insensitive_backend(self):
        s = SimpleNamespace(secrets_backend="ENV")
        assert isinstance(build_secrets_provider(s), EnvSecrets)
