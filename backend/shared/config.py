"""
Centralized configuration management for Sentry.
Uses environment variables with secure defaults following 12-factor app principles.
"""

import os
from dataclasses import dataclass, field
from dotenv import load_dotenv
from enum import Enum
from typing import FrozenSet


class SentryMode(Enum):
    """Operating modes for Sentry."""
    ACTIVE = "ACTIVE"    # Full autonomous operation
    AUDIT = "AUDIT"      # Log-only mode for active tools
    DISABLED = "DISABLED" # All operations disabled


class EffortLevel(Enum):
    """Opus thinking effort levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class SecurityConfig:
    """Immutable security configuration - Defense in Depth."""
    mode: SentryMode = SentryMode.AUDIT  # Default to AUDIT (safe)
    stop_file_path: str = "/app/STOP_SENTRY"
    max_cost_per_10min_usd: float = 5.00
    max_retries: int = 3
    restart_cooldown_seconds: int = 600  # 10 minutes
    allowed_diagnostic_commands: FrozenSet[str] = field(default_factory=lambda: frozenset({
        "ps aux", "netstat -tlnp", "curl", "tail", "df -h",
        "free -m", "uptime", "systemctl status",
        "docker ps", "docker inspect", "docker logs",
        "ping", "dig", "cat /proc/meminfo", "lsof -i",
        "find", "ls",
    }))
    allowed_fetch_domains: FrozenSet[str] = field(default_factory=lambda: frozenset({
        "docs.python.org", "stackoverflow.com", "linux.die.net",
        "man7.org", "nginx.org", "postgresql.org",
    }))
    project_root: str = "/app/workspace"
    max_grep_results: int = 100
    max_file_size_bytes: int = 1_048_576  # 1MB


class LLMProvider(Enum):
    """LLM provider selection."""
    ANTHROPIC = "anthropic"
    BEDROCK_GATEWAY = "bedrock_gateway"


@dataclass(frozen=True)
class AnthropicConfig:
    """Anthropic API configuration."""
    api_key: str = ""
    model: str = "claude-opus-4-0-20250514"
    max_tokens: int = 16384
    api_base_url: str = "https://api.anthropic.com"


@dataclass(frozen=True)
class BedrockGatewayConfig:
    """AWS Bedrock Access Gateway (OpenAI-compatible) configuration."""
    api_key: str = ""  # Gateway API key
    base_url: str = ""  # e.g. https://your-gateway.execute-api.us-east-1.amazonaws.com/api/v1
    model: str = "anthropic.claude-opus-4-0-20250514"  # Bedrock model ID
    max_tokens: int = 16384


@dataclass(frozen=True)
class WatcherConfig:
    """Log watcher configuration."""
    watch_paths: tuple = ("/var/log/syslog", "/var/log/app/*.log")
    poll_interval_seconds: float = 2.0
    error_patterns: tuple = (
        r"(?i)error", r"(?i)critical", r"(?i)fatal",
        r"(?i)exception", r"(?i)refused", r"(?i)timeout",
        r"(?i)out of memory", r"(?i)disk full", r"(?i)502",
        r"(?i)503", r"(?i)connection reset",
    )


@dataclass(frozen=True)
class MemoryConfig:
    """Memory store configuration."""
    file_path: str = "/app/data/sentry_memory.json"
    max_incidents_before_compaction: int = 50
    backup_on_write: bool = True


@dataclass(frozen=True)
class AppConfig:
    """Root application configuration - assembled from environment."""
    security: SecurityConfig = field(default_factory=SecurityConfig)
    anthropic: AnthropicConfig = field(default_factory=AnthropicConfig)
    bedrock_gateway: BedrockGatewayConfig = field(default_factory=BedrockGatewayConfig)
    llm_provider: LLMProvider = LLMProvider.ANTHROPIC
    watcher: WatcherConfig = field(default_factory=WatcherConfig)
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    audit_log_path: str = "/app/data/audit.jsonl"
    service_source_path: str = "/app/workspace"
    log_file_dir: str = ""  # Directory for timestamped log files; empty = no file logging
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    log_level: str = "INFO"
    environment: str = "production"


def load_config() -> AppConfig:
    """
    Load configuration from environment variables.
    Secure defaults are used when env vars are not set.
    """
    load_dotenv()  # Load .env file if present
    mode_str = os.environ.get("SENTRY_MODE", "AUDIT").upper()
    try:
        mode = SentryMode(mode_str)
    except ValueError:
        mode = SentryMode.AUDIT  # Fail safe

    security = SecurityConfig(
        mode=mode,
        stop_file_path=os.environ.get("STOP_FILE_PATH", "/app/STOP_SENTRY"),
        max_cost_per_10min_usd=float(os.environ.get("MAX_COST_10MIN", "5.00")),
        max_retries=int(os.environ.get("MAX_RETRIES", "3")),
        restart_cooldown_seconds=int(os.environ.get("RESTART_COOLDOWN", "600")),
        project_root=os.environ.get("PROJECT_ROOT", "/app/workspace"),
    )

    anthropic = AnthropicConfig(
        api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        model=os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-0-20250514"),
        max_tokens=int(os.environ.get("ANTHROPIC_MAX_TOKENS", "16384")),
    )

    watcher_paths = os.environ.get("WATCH_PATHS", "/var/log/syslog,/var/log/app/*.log")
    watcher = WatcherConfig(
        watch_paths=tuple(watcher_paths.split(",")),
        poll_interval_seconds=float(os.environ.get("POLL_INTERVAL", "2.0")),
    )

    memory = MemoryConfig(
        file_path=os.environ.get("MEMORY_FILE_PATH", "/app/data/sentry_memory.json"),
        max_incidents_before_compaction=int(os.environ.get("MAX_INCIDENTS_COMPACT", "50")),
    )

    bedrock_gw = BedrockGatewayConfig(
        api_key=os.environ.get("BEDROCK_GATEWAY_API_KEY", ""),
        base_url=os.environ.get("BEDROCK_GATEWAY_BASE_URL", ""),
        model=os.environ.get("BEDROCK_GATEWAY_MODEL", "anthropic.claude-opus-4-0-20250514"),
        max_tokens=int(os.environ.get("BEDROCK_GATEWAY_MAX_TOKENS", "16384")),
    )

    provider_str = os.environ.get("LLM_PROVIDER", "anthropic").lower()
    try:
        llm_provider = LLMProvider(provider_str)
    except ValueError:
        llm_provider = LLMProvider.ANTHROPIC

    return AppConfig(
        security=security,
        anthropic=anthropic,
        bedrock_gateway=bedrock_gw,
        llm_provider=llm_provider,
        watcher=watcher,
        memory=memory,
        service_source_path=os.environ.get("SERVICE_SOURCE_PATH", "/app/workspace"),
        log_file_dir=os.environ.get("LOG_FILE_DIR", ""),
        api_host=os.environ.get("API_HOST", "0.0.0.0"),
        api_port=int(os.environ.get("API_PORT", "8000")),
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
        environment=os.environ.get("ENVIRONMENT", "production"),
    )
