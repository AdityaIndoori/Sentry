"""
P1.1 — Pydantic-settings v2 based configuration.

This module is the single-source-of-truth settings layer. It wraps the
existing dataclass-based ``AppConfig`` so the rest of the codebase keeps
working unchanged, while giving the composition root (``backend.shared.factory``)
a validated, typed, env-driven entrypoint.

Design constraints
------------------
* Backwards-compatible with ``backend.shared.config.load_config()`` — we
  delegate to the same environment contract. ``load_config()`` continues
  to return an ``AppConfig`` dataclass.
* Zero new dependencies are required at import time: if
  ``pydantic_settings`` is installed we use it for validation, otherwise
  we fall back to a hand-rolled ``Settings`` that reads the same env
  vars. Either way ``get_settings()`` returns a ``Settings`` instance
  carrying ``to_app_config()``.
* Adds a handful of new settings that downstream phases (P1.2 Postgres,
  P1.4 Vault JIT, P2.x auth + observability) will consume. These are all
  optional with safe defaults so existing deployments keep booting.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, Optional, Tuple

from dotenv import load_dotenv

from backend.shared.config import (
    AnthropicConfig,
    AppConfig,
    BedrockGatewayConfig,
    LLMProvider,
    MemoryConfig,
    SecurityConfig,
    SentryMode,
    WatcherConfig,
)


# ---------------------------------------------------------------------------
# Try to use pydantic-settings v2 for real validation; fall back to a plain
# dataclass if the package isn't installed (older envs).
# ---------------------------------------------------------------------------
try:  # pragma: no cover - exercised implicitly
    from pydantic_settings import BaseSettings, SettingsConfigDict
    _HAS_PYDANTIC_SETTINGS = True
except Exception:  # pragma: no cover
    BaseSettings = object  # type: ignore[assignment,misc]
    SettingsConfigDict = dict  # type: ignore[assignment,misc]
    _HAS_PYDANTIC_SETTINGS = False


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    val = os.environ.get(name)
    return val if val is not None else default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    """
    Flat, typed settings object. Not a Pydantic model directly — it is
    built by :func:`get_settings`, which uses pydantic-settings for
    validation when available and this dataclass as the return shape
    either way. Keeping a dataclass return type means the container,
    factory, and tests don't depend on the pydantic version.
    """

    # --- Core operating mode -------------------------------------------------
    mode: SentryMode = SentryMode.AUDIT
    environment: str = "production"
    log_level: str = "INFO"
    log_file_dir: str = ""

    # --- LLM provider --------------------------------------------------------
    llm_provider: LLMProvider = LLMProvider.ANTHROPIC
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-opus-4-0-20250514"
    anthropic_max_tokens: int = 16384
    bedrock_gateway_api_key: str = ""
    bedrock_gateway_base_url: str = ""
    bedrock_gateway_model: str = "anthropic.claude-opus-4-0-20250514"
    bedrock_gateway_max_tokens: int = 16384

    # --- Security ------------------------------------------------------------
    stop_file_path: str = "/app/STOP_SENTRY"
    max_cost_per_10min_usd: float = 5.00
    max_retries: int = 3
    restart_cooldown_seconds: int = 600
    project_root: str = "/app/workspace"
    patchable_root: str = "/app/patchable"
    service_source_path: str = "/app/workspace"

    # --- Audit + memory ------------------------------------------------------
    audit_log_path: str = "/app/data/audit.jsonl"
    memory_file_path: str = "/app/data/sentry_memory.json"
    memory_max_incidents_before_compaction: int = 50

    # --- Watcher -------------------------------------------------------------
    watch_paths: Tuple[str, ...] = ("/var/log/syslog", "/var/log/app/*.log")
    poll_interval_seconds: float = 2.0

    # --- API server ----------------------------------------------------------
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # --- P1.2 / P1.4 / P2.x forward-looking knobs (unused yet) ---------------
    database_url: Optional[str] = None
    api_auth_token: Optional[str] = None
    secrets_backend: str = "env"  # env | file | sops | vault
    secrets_vault_addr: Optional[str] = None
    secrets_vault_role: Optional[str] = None
    secrets_sops_file: Optional[str] = None
    otel_exporter_otlp_endpoint: Optional[str] = None
    prometheus_enabled: bool = True
    service_name: str = "sentry"
    orchestrator_timeout_seconds: int = 300
    auto_commit_enabled: bool = False

    # ------------------------------------------------------------------------
    def to_app_config(self) -> AppConfig:
        """Render this settings object as the legacy ``AppConfig`` dataclass."""
        security = SecurityConfig(
            mode=self.mode,
            stop_file_path=self.stop_file_path,
            max_cost_per_10min_usd=self.max_cost_per_10min_usd,
            max_retries=self.max_retries,
            restart_cooldown_seconds=self.restart_cooldown_seconds,
            project_root=self.project_root,
            patchable_root=self.patchable_root,
        )
        anthropic = AnthropicConfig(
            api_key=self.anthropic_api_key,
            model=self.anthropic_model,
            max_tokens=self.anthropic_max_tokens,
        )
        bedrock = BedrockGatewayConfig(
            api_key=self.bedrock_gateway_api_key,
            base_url=self.bedrock_gateway_base_url,
            model=self.bedrock_gateway_model,
            max_tokens=self.bedrock_gateway_max_tokens,
        )
        watcher = WatcherConfig(
            watch_paths=self.watch_paths,
            poll_interval_seconds=self.poll_interval_seconds,
        )
        memory = MemoryConfig(
            file_path=self.memory_file_path,
            max_incidents_before_compaction=self.memory_max_incidents_before_compaction,
        )
        return AppConfig(
            security=security,
            anthropic=anthropic,
            bedrock_gateway=bedrock,
            llm_provider=self.llm_provider,
            watcher=watcher,
            memory=memory,
            audit_log_path=self.audit_log_path,
            service_source_path=self.service_source_path,
            log_file_dir=self.log_file_dir,
            api_host=self.api_host,
            api_port=self.api_port,
            log_level=self.log_level,
            environment=self.environment,
        )


# ---------------------------------------------------------------------------
# Pydantic-settings v2 wrapper (optional).
# ---------------------------------------------------------------------------
if _HAS_PYDANTIC_SETTINGS:

    class _PydanticSettings(BaseSettings):  # type: ignore[misc,valid-type]
        """Pydantic v2 model for env parsing + validation."""

        model_config = SettingsConfigDict(
            env_file=".env",
            env_file_encoding="utf-8",
            extra="ignore",
            case_sensitive=False,
        )

        SENTRY_MODE: str = "AUDIT"
        ENVIRONMENT: str = "production"
        LOG_LEVEL: str = "INFO"
        LOG_FILE_DIR: str = ""

        LLM_PROVIDER: str = "anthropic"
        ANTHROPIC_API_KEY: str = ""
        ANTHROPIC_MODEL: str = "claude-opus-4-0-20250514"
        ANTHROPIC_MAX_TOKENS: int = 16384
        BEDROCK_GATEWAY_API_KEY: str = ""
        BEDROCK_GATEWAY_BASE_URL: str = ""
        BEDROCK_GATEWAY_MODEL: str = "anthropic.claude-opus-4-0-20250514"
        BEDROCK_GATEWAY_MAX_TOKENS: int = 16384

        STOP_FILE_PATH: str = "/app/STOP_SENTRY"
        MAX_COST_10MIN: float = 5.00
        MAX_RETRIES: int = 3
        RESTART_COOLDOWN: int = 600
        PROJECT_ROOT: str = "/app/workspace"
        PATCHABLE_ROOT: str = "/app/patchable"
        SERVICE_SOURCE_PATH: str = "/app/workspace"

        AUDIT_LOG_PATH: str = "/app/data/audit.jsonl"
        MEMORY_FILE_PATH: str = "/app/data/sentry_memory.json"
        MAX_INCIDENTS_COMPACT: int = 50

        WATCH_PATHS: str = "/var/log/syslog,/var/log/app/*.log"
        POLL_INTERVAL: float = 2.0

        API_HOST: str = "0.0.0.0"
        API_PORT: int = 8000

        DATABASE_URL: Optional[str] = None
        API_AUTH_TOKEN: Optional[str] = None
        SECRETS_BACKEND: str = "env"
        SECRETS_VAULT_ADDR: Optional[str] = None
        SECRETS_VAULT_ROLE: Optional[str] = None
        SECRETS_SOPS_FILE: Optional[str] = None
        OTEL_EXPORTER_OTLP_ENDPOINT: Optional[str] = None
        PROMETHEUS_ENABLED: bool = True
        SERVICE_NAME: str = "sentry"
        ORCHESTRATOR_TIMEOUT_SECONDS: int = 300
        AUTO_COMMIT_ENABLED: bool = False

        def to_settings(self) -> Settings:
            try:
                mode = SentryMode(self.SENTRY_MODE.upper())
            except ValueError:
                mode = SentryMode.AUDIT
            try:
                provider = LLMProvider(self.LLM_PROVIDER.lower())
            except ValueError:
                provider = LLMProvider.ANTHROPIC
            return Settings(
                mode=mode,
                environment=self.ENVIRONMENT,
                log_level=self.LOG_LEVEL,
                log_file_dir=self.LOG_FILE_DIR,
                llm_provider=provider,
                anthropic_api_key=self.ANTHROPIC_API_KEY,
                anthropic_model=self.ANTHROPIC_MODEL,
                anthropic_max_tokens=self.ANTHROPIC_MAX_TOKENS,
                bedrock_gateway_api_key=self.BEDROCK_GATEWAY_API_KEY,
                bedrock_gateway_base_url=self.BEDROCK_GATEWAY_BASE_URL,
                bedrock_gateway_model=self.BEDROCK_GATEWAY_MODEL,
                bedrock_gateway_max_tokens=self.BEDROCK_GATEWAY_MAX_TOKENS,
                stop_file_path=self.STOP_FILE_PATH,
                max_cost_per_10min_usd=self.MAX_COST_10MIN,
                max_retries=self.MAX_RETRIES,
                restart_cooldown_seconds=self.RESTART_COOLDOWN,
                project_root=self.PROJECT_ROOT,
                patchable_root=self.PATCHABLE_ROOT,
                service_source_path=self.SERVICE_SOURCE_PATH,
                audit_log_path=self.AUDIT_LOG_PATH,
                memory_file_path=self.MEMORY_FILE_PATH,
                memory_max_incidents_before_compaction=self.MAX_INCIDENTS_COMPACT,
                watch_paths=tuple(p for p in self.WATCH_PATHS.split(",") if p),
                poll_interval_seconds=self.POLL_INTERVAL,
                api_host=self.API_HOST,
                api_port=self.API_PORT,
                database_url=self.DATABASE_URL,
                api_auth_token=self.API_AUTH_TOKEN,
                secrets_backend=self.SECRETS_BACKEND,
                secrets_vault_addr=self.SECRETS_VAULT_ADDR,
                secrets_vault_role=self.SECRETS_VAULT_ROLE,
                secrets_sops_file=self.SECRETS_SOPS_FILE,
                otel_exporter_otlp_endpoint=self.OTEL_EXPORTER_OTLP_ENDPOINT,
                prometheus_enabled=self.PROMETHEUS_ENABLED,
                service_name=self.SERVICE_NAME,
                orchestrator_timeout_seconds=self.ORCHESTRATOR_TIMEOUT_SECONDS,
                auto_commit_enabled=self.AUTO_COMMIT_ENABLED,
            )


def _build_settings_from_env() -> Settings:
    """Fallback path when pydantic-settings isn't installed."""
    load_dotenv()
    try:
        mode = SentryMode((_env("SENTRY_MODE", "AUDIT") or "AUDIT").upper())
    except ValueError:
        mode = SentryMode.AUDIT
    try:
        provider = LLMProvider((_env("LLM_PROVIDER", "anthropic") or "anthropic").lower())
    except ValueError:
        provider = LLMProvider.ANTHROPIC

    watch_paths_raw = _env("WATCH_PATHS", "/var/log/syslog,/var/log/app/*.log") or ""
    watch_paths = tuple(p for p in watch_paths_raw.split(",") if p)

    return Settings(
        mode=mode,
        environment=_env("ENVIRONMENT", "production") or "production",
        log_level=_env("LOG_LEVEL", "INFO") or "INFO",
        log_file_dir=_env("LOG_FILE_DIR", "") or "",
        llm_provider=provider,
        anthropic_api_key=_env("ANTHROPIC_API_KEY", "") or "",
        anthropic_model=_env("ANTHROPIC_MODEL", "claude-opus-4-0-20250514") or "claude-opus-4-0-20250514",
        anthropic_max_tokens=_env_int("ANTHROPIC_MAX_TOKENS", 16384),
        bedrock_gateway_api_key=_env("BEDROCK_GATEWAY_API_KEY", "") or "",
        bedrock_gateway_base_url=_env("BEDROCK_GATEWAY_BASE_URL", "") or "",
        bedrock_gateway_model=_env("BEDROCK_GATEWAY_MODEL", "anthropic.claude-opus-4-0-20250514")
        or "anthropic.claude-opus-4-0-20250514",
        bedrock_gateway_max_tokens=_env_int("BEDROCK_GATEWAY_MAX_TOKENS", 16384),
        stop_file_path=_env("STOP_FILE_PATH", "/app/STOP_SENTRY") or "/app/STOP_SENTRY",
        max_cost_per_10min_usd=_env_float("MAX_COST_10MIN", 5.00),
        max_retries=_env_int("MAX_RETRIES", 3),
        restart_cooldown_seconds=_env_int("RESTART_COOLDOWN", 600),
        project_root=_env("PROJECT_ROOT", "/app/workspace") or "/app/workspace",
        patchable_root=_env("PATCHABLE_ROOT", "/app/patchable") or "/app/patchable",
        service_source_path=_env("SERVICE_SOURCE_PATH", "/app/workspace") or "/app/workspace",
        audit_log_path=_env("AUDIT_LOG_PATH", "/app/data/audit.jsonl") or "/app/data/audit.jsonl",
        memory_file_path=_env("MEMORY_FILE_PATH", "/app/data/sentry_memory.json")
        or "/app/data/sentry_memory.json",
        memory_max_incidents_before_compaction=_env_int("MAX_INCIDENTS_COMPACT", 50),
        watch_paths=watch_paths,
        poll_interval_seconds=_env_float("POLL_INTERVAL", 2.0),
        api_host=_env("API_HOST", "0.0.0.0") or "0.0.0.0",
        api_port=_env_int("API_PORT", 8000),
        database_url=_env("DATABASE_URL"),
        api_auth_token=_env("API_AUTH_TOKEN"),
        secrets_backend=_env("SECRETS_BACKEND", "env") or "env",
        secrets_vault_addr=_env("SECRETS_VAULT_ADDR"),
        secrets_vault_role=_env("SECRETS_VAULT_ROLE"),
        secrets_sops_file=_env("SECRETS_SOPS_FILE"),
        otel_exporter_otlp_endpoint=_env("OTEL_EXPORTER_OTLP_ENDPOINT"),
        prometheus_enabled=_env_bool("PROMETHEUS_ENABLED", True),
        service_name=_env("SERVICE_NAME", "sentry") or "sentry",
        orchestrator_timeout_seconds=_env_int("ORCHESTRATOR_TIMEOUT_SECONDS", 300),
        auto_commit_enabled=_env_bool("AUTO_COMMIT_ENABLED", False),
    )


def get_settings(*, reload: bool = False) -> Settings:
    """
    Return the current process Settings.

    Uses pydantic-settings for validation when installed; otherwise falls
    back to a hand-rolled env reader with the same contract.

    ``reload=True`` bypasses any cache — useful in tests that
    ``patch.dict(os.environ, ...)``.
    """
    if reload:
        _cached_settings.cache_clear()
    return _cached_settings()


@lru_cache(maxsize=1)
def _cached_settings() -> Settings:
    load_dotenv()
    if _HAS_PYDANTIC_SETTINGS:
        try:
            return _PydanticSettings().to_settings()  # type: ignore[name-defined]
        except Exception:  # pragma: no cover - defensive, fall through
            return _build_settings_from_env()
    return _build_settings_from_env()


__all__ = ["Settings", "get_settings"]
