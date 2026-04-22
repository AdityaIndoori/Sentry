"""
P2.2 — Open-source secrets provider abstraction.

The production deployment pulls ``ANTHROPIC_API_KEY``, ``API_AUTH_TOKEN``,
and ``DATABASE_URL`` through an :class:`ISecretsProvider` so the operator
can pick exactly one of four **fully open-source** backends:

* ``env``  — process environment (dev fallback).
* ``file`` — files under ``/run/secrets/<name>`` (docker-compose
  ``secrets:`` / tmpfs; the Docker Swarm convention).
* ``sops`` — a sops-age-encrypted YAML decrypted at startup via the
  ``sops`` CLI. Fully offline, GitOps-friendly.
* ``vault``— HashiCorp Vault OSS / OpenBao via the ``hvac`` client.
  Token or AppRole auth; supports KVv1 and KVv2 mounts.

Selection lives on ``Settings.secrets_backend`` and defaults to ``env``
so existing deployments keep booting without any new configuration.
This module is intentionally dependency-light: ``hvac`` is imported
lazily only when ``VaultSecrets`` is instantiated, and the ``sops`` CLI
is only invoked by ``SopsSecrets`` at ``get()`` time.

Every provider returns the raw secret **value**, never the key; the
key is a logical name like ``"anthropic_api_key"`` or
``"database_url"``. It's up to the caller (the container factory) to
map logical names to the underlying store's path/env-var/file name.

.. note::

   P2.1 bootstraps a single admin token from ``API_AUTH_TOKEN`` via
   :func:`backend.api.auth.seed_tokens_from_settings`. P2.2 doesn't
   *replace* that path — it makes it possible to load that env var
   from a non-env source (``secrets/api_auth_token``, sops, or Vault).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------


class ISecretsProvider(ABC):
    """Unified secret lookup interface.

    All implementations are synchronous because startup secret
    resolution happens exactly once, before the event loop begins. A
    provider instance is safe to share across threads — state is
    either immutable (sops snapshot) or read-only (env/file/vault) in
    practice.
    """

    @abstractmethod
    def get(self, name: str) -> Optional[str]:
        """Return the secret for logical name ``name`` or None if absent."""

    def require(self, name: str) -> str:
        """Like :meth:`get` but raise :class:`KeyError` on miss.

        Used at startup for genuinely required secrets (e.g. Anthropic
        API key in production) so a missing secret fails fast with a
        clear message instead of silently passing an empty string to
        downstream code.
        """
        value = self.get(name)
        if value is None or value == "":
            raise KeyError(
                f"Secret '{name}' not found in {self.__class__.__name__}"
            )
        return value


# ---------------------------------------------------------------------------
# 1) Env provider  — the dev fallback.
# ---------------------------------------------------------------------------


class EnvSecrets(ISecretsProvider):
    """Resolve secrets from the process environment.

    Lookup order:

    1. ``SECRET_<NAME>`` (uppercase). The ``SECRET_`` prefix discourages
       accidental collisions with plain config vars.
    2. ``<NAME>`` (uppercase). Fallback for legacy configurations like
       ``ANTHROPIC_API_KEY``.

    Returns ``None`` if neither exists.
    """

    def __init__(self, prefix: str = "SECRET_"):
        self._prefix = prefix

    def get(self, name: str) -> Optional[str]:
        upper = name.upper()
        val = os.environ.get(self._prefix + upper)
        if val is not None:
            return val
        return os.environ.get(upper)


# ---------------------------------------------------------------------------
# 2) File provider — docker-compose `secrets:` / tmpfs mounts.
# ---------------------------------------------------------------------------


class FileSecrets(ISecretsProvider):
    """Resolve secrets from ``<root>/<name>`` files.

    Docker Swarm / Compose mount each secret as a read-only file under
    ``/run/secrets/<name>``. This provider simply reads and strips
    trailing newlines so the operator can store the value with a
    trailing newline without breaking lookups.

    ``root`` defaults to ``/run/secrets`` but is configurable for tests
    and for non-standard mount points.
    """

    def __init__(self, root: str = "/run/secrets"):
        self._root = Path(root)

    def get(self, name: str) -> Optional[str]:
        path = self._root / name
        try:
            return path.read_text(encoding="utf-8").rstrip("\r\n")
        except FileNotFoundError:
            return None
        except PermissionError:
            logger.warning(
                "Secret file %s is not readable — check docker-compose "
                "`secrets:` mode / file permissions.",
                path,
            )
            return None


# ---------------------------------------------------------------------------
# 3) sops + age provider — fully offline, GitOps-friendly.
# ---------------------------------------------------------------------------


class SopsSecrets(ISecretsProvider):
    """Resolve secrets from a sops-age-encrypted YAML/JSON file.

    The file is decrypted **once at construction time** via the ``sops``
    CLI (``sops -d <file>``). The decrypted payload stays in memory
    only; nothing is written to disk. Supports nested keys through dot
    notation (``"db.password"`` → ``payload["db"]["password"]``).

    Requirements at runtime:

    * ``sops`` must be on PATH.
    * The age identity (``SOPS_AGE_KEY`` env var or
      ``~/.config/sops/age/keys.txt``) must be accessible.

    If ``sops`` isn't installed or the file cannot be decrypted we
    raise :class:`RuntimeError` immediately — a missing secrets
    backend should never silently fall back to an empty config.

    This class depends only on the ``sops`` binary; no Python
    packages beyond PyYAML (stdlib in many envs via ``pip install
    PyYAML``; gracefully degraded to JSON if YAML isn't installed).
    """

    def __init__(self, sops_file: str):
        self._file = sops_file
        self._payload: Dict[str, Any] = self._decrypt(sops_file)

    @staticmethod
    def _decrypt(sops_file: str) -> Dict[str, Any]:
        if shutil.which("sops") is None:
            raise RuntimeError(
                "SopsSecrets: `sops` CLI not found on PATH. "
                "Install from https://github.com/getsops/sops/releases."
            )
        try:
            proc = subprocess.run(
                ["sops", "-d", sops_file],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:  # pragma: no cover — runtime only
            raise RuntimeError(
                f"SopsSecrets: `sops -d {sops_file}` failed: "
                f"{exc.stderr.strip() or exc}"
            ) from exc
        return _parse_structured(proc.stdout)

    def get(self, name: str) -> Optional[str]:
        """Look up by dotted path; returns None on miss."""
        node: Any = self._payload
        for part in name.split("."):
            if not isinstance(node, dict):
                return None
            node = node.get(part)
            if node is None:
                return None
        if isinstance(node, str):
            return node
        # Numbers / bools are stringified so callers always get str.
        if isinstance(node, (int, float, bool)):
            return str(node)
        return None


def _parse_structured(text: str) -> Dict[str, Any]:
    """Parse a YAML (preferred) or JSON payload into a dict.

    We try YAML first because sops commonly targets YAML; if PyYAML
    isn't installed we try JSON. Both are common sops-encrypted
    formats. No third dependency is pulled in.
    """
    text = text.lstrip()
    try:
        import yaml  # type: ignore
    except Exception:  # pragma: no cover
        yaml = None  # type: ignore

    if yaml is not None:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict):
                return data
        except Exception:  # pragma: no cover
            pass

    import json
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "SopsSecrets: decrypted payload is neither valid YAML nor JSON "
            f"— {exc}"
        ) from exc
    raise RuntimeError(
        "SopsSecrets: decrypted payload did not parse to a mapping "
        "— expected a YAML/JSON object at the top level."
    )


# ---------------------------------------------------------------------------
# 4) Vault / OpenBao provider — production backend.
# ---------------------------------------------------------------------------


class VaultSecrets(ISecretsProvider):
    """Resolve secrets from HashiCorp Vault OSS / OpenBao.

    Reads secret values from the KVv2 mount ``secret/data/sentry/<name>``
    by default (override via ``mount`` + ``base_path`` kwargs).
    Authentication methods:

    * ``token=<vault_token>`` — simplest, used by tests and by small
      deployments with a long-lived token stored in a sealed file.
    * ``role_id`` + ``secret_id`` — AppRole auth, suitable for
      production where the sidecar provisions a short-lived token.

    The ``hvac`` client is imported lazily so that non-vault
    deployments don't pay the import cost. Results are cached
    in-process for ``cache_ttl_seconds`` (default 300) to cut down
    Vault round-trips during burst load.
    """

    def __init__(
        self,
        addr: str,
        *,
        token: Optional[str] = None,
        role_id: Optional[str] = None,
        secret_id: Optional[str] = None,
        mount: str = "secret",
        base_path: str = "sentry",
        cache_ttl_seconds: int = 300,
    ):
        try:
            import hvac  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "VaultSecrets requires the `hvac` package. Install it with "
                "`pip install hvac` or set SECRETS_BACKEND to 'env'/'file'/'sops'."
            ) from exc

        self._client = hvac.Client(url=addr)
        self._mount = mount
        self._base = base_path.strip("/")
        self._cache_ttl = cache_ttl_seconds
        self._cache: Dict[str, tuple[float, str]] = {}

        if token:
            self._client.token = token
        elif role_id and secret_id:  # pragma: no cover — runtime only
            self._client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        else:
            raise RuntimeError(
                "VaultSecrets: no credentials provided "
                "(need `token` or `role_id`+`secret_id`)."
            )

        if not self._client.is_authenticated():  # pragma: no cover — runtime only
            raise RuntimeError(
                f"VaultSecrets: client failed to authenticate to {addr}."
            )

    def get(self, name: str) -> Optional[str]:
        import time
        now = time.time()
        cached = self._cache.get(name)
        if cached is not None and now - cached[0] < self._cache_ttl:
            return cached[1]

        try:  # pragma: no cover — runtime only
            path = f"{self._base}/{name}" if self._base else name
            resp = self._client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=self._mount,
            )
            data = (resp or {}).get("data", {}).get("data", {})
            # Vault KVv2 stores arbitrary key/value pairs; the canonical
            # shape is {"value": "<raw>"} but we also accept the secret
            # name itself as the inner key.
            value = data.get("value") or data.get(name)
            if isinstance(value, (int, float, bool)):
                value = str(value)
            if isinstance(value, str):
                self._cache[name] = (now, value)
                return value
            return None
        except Exception as exc:  # pragma: no cover — runtime only
            logger.warning("VaultSecrets.get(%s) failed: %s", name, exc)
            return None


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_secrets_provider(settings: Any) -> ISecretsProvider:
    """Pick an :class:`ISecretsProvider` implementation from settings.

    Uses these ``Settings`` fields (all already present on
    :class:`backend.shared.settings.Settings`):

    * ``secrets_backend``: one of ``"env"`` / ``"file"`` / ``"sops"`` /
      ``"vault"``. Unknown values fall back to ``"env"`` with a
      warning — a misconfigured deployment shouldn't just boot with no
      secrets.
    * ``secrets_vault_addr`` + optional ``secrets_vault_role`` +
      ``SECRET_VAULT_TOKEN`` env var (for vault).
    * ``secrets_sops_file`` (for sops).

    Any runtime errors from the chosen backend propagate so the
    process fails fast at startup rather than silently running with
    missing credentials.
    """
    backend = (getattr(settings, "secrets_backend", "env") or "env").strip().lower()

    if backend == "env":
        return EnvSecrets()

    if backend == "file":
        # Default root is /run/secrets (docker-compose secrets:). Tests
        # and non-Linux deployments override via FILE_SECRETS_ROOT.
        root = os.environ.get("FILE_SECRETS_ROOT", "/run/secrets")
        return FileSecrets(root=root)

    if backend == "sops":
        sops_file = getattr(settings, "secrets_sops_file", None)
        if not sops_file:
            raise RuntimeError(
                "secrets_backend=sops requires settings.secrets_sops_file"
            )
        return SopsSecrets(sops_file=sops_file)

    if backend == "vault":
        addr = getattr(settings, "secrets_vault_addr", None)
        if not addr:
            raise RuntimeError(
                "secrets_backend=vault requires settings.secrets_vault_addr"
            )
        token = os.environ.get("VAULT_TOKEN") or os.environ.get("SECRET_VAULT_TOKEN")
        role_id = os.environ.get("VAULT_ROLE_ID")
        secret_id = os.environ.get("VAULT_SECRET_ID")
        return VaultSecrets(
            addr=addr, token=token, role_id=role_id, secret_id=secret_id,
        )

    logger.warning(
        "Unknown SECRETS_BACKEND=%r — falling back to env provider", backend,
    )
    return EnvSecrets()


__all__ = [
    "ISecretsProvider",
    "EnvSecrets",
    "FileSecrets",
    "SopsSecrets",
    "VaultSecrets",
    "build_secrets_provider",
]
