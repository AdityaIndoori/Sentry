"""
Tests for shared/config.py — configuration loading and defaults.
"""

import os
import pytest
from unittest.mock import patch

from backend.shared.config import (
    SentryMode, EffortLevel, LLMProvider,
    SecurityConfig, AnthropicConfig, BedrockGatewayConfig,
    WatcherConfig, MemoryConfig, AppConfig,
    load_config,
)


class TestSentryMode:
    def test_active(self):
        assert SentryMode("ACTIVE") == SentryMode.ACTIVE

    def test_audit(self):
        assert SentryMode("AUDIT") == SentryMode.AUDIT

    def test_disabled(self):
        assert SentryMode("DISABLED") == SentryMode.DISABLED


class TestSecurityConfigDefaults:
    def test_default_mode_is_audit(self):
        cfg = SecurityConfig()
        assert cfg.mode == SentryMode.AUDIT

    def test_default_max_cost(self):
        cfg = SecurityConfig()
        assert cfg.max_cost_per_10min_usd == 5.00

    def test_allowed_commands_are_frozen(self):
        cfg = SecurityConfig()
        assert "ps aux" in cfg.allowed_diagnostic_commands
        assert isinstance(cfg.allowed_diagnostic_commands, frozenset)


class TestAppConfigDefaults:
    def test_default_provider_is_anthropic(self):
        cfg = AppConfig()
        assert cfg.llm_provider == LLMProvider.ANTHROPIC

    def test_default_log_level(self):
        cfg = AppConfig()
        assert cfg.log_level == "INFO"

    def test_default_environment(self):
        cfg = AppConfig()
        assert cfg.environment == "production"


class TestLoadConfig:
    @patch.dict(os.environ, {
        "SENTRY_MODE": "ACTIVE",
        "ANTHROPIC_API_KEY": "sk-ant-test",
        "WATCH_PATHS": "/var/log/app.log,/var/log/error.log",
        "LOG_LEVEL": "DEBUG",
        "ENVIRONMENT": "testing",
        "LLM_PROVIDER": "anthropic",
        "MAX_COST_10MIN": "10.0",
        "POLL_INTERVAL": "5.0",
    }, clear=False)
    def test_loads_from_env(self):
        cfg = load_config()
        assert cfg.security.mode == SentryMode.ACTIVE
        assert cfg.anthropic.api_key == "sk-ant-test"
        assert "/var/log/app.log" in cfg.watcher.watch_paths
        assert "/var/log/error.log" in cfg.watcher.watch_paths
        assert cfg.log_level == "DEBUG"
        assert cfg.environment == "testing"
        assert cfg.security.max_cost_per_10min_usd == 10.0
        assert cfg.watcher.poll_interval_seconds == 5.0

    @patch.dict(os.environ, {"SENTRY_MODE": "INVALID_MODE"}, clear=False)
    def test_invalid_mode_defaults_to_audit(self):
        cfg = load_config()
        assert cfg.security.mode == SentryMode.AUDIT

    @patch.dict(os.environ, {"LLM_PROVIDER": "bedrock_gateway"}, clear=False)
    def test_bedrock_gateway_provider(self):
        cfg = load_config()
        assert cfg.llm_provider == LLMProvider.BEDROCK_GATEWAY

    @patch.dict(os.environ, {"LLM_PROVIDER": "invalid_provider"}, clear=False)
    def test_invalid_provider_defaults_to_anthropic(self):
        cfg = load_config()
        assert cfg.llm_provider == LLMProvider.ANTHROPIC

    @patch.dict(os.environ, {}, clear=False)
    def test_defaults_when_no_env(self):
        # Remove specific keys to test defaults
        env_copy = os.environ.copy()
        for key in ["SENTRY_MODE", "ANTHROPIC_API_KEY", "LLM_PROVIDER"]:
            env_copy.pop(key, None)
        with patch.dict(os.environ, env_copy, clear=True), \
             patch("backend.shared.config.load_dotenv"):  # prevent .env file from overriding
            cfg = load_config()
            assert cfg.security.mode == SentryMode.AUDIT
            assert cfg.llm_provider == LLMProvider.ANTHROPIC
