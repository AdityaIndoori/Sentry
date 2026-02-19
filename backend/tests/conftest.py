"""
Shared test fixtures for Sentry test suite.
"""

import os
import sys
import tempfile

import pytest

# Ensure backend is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.shared.config import (
    AppConfig, AnthropicConfig, MemoryConfig,
    SecurityConfig, SentryMode, WatcherConfig,
)
from backend.shared.security import SecurityGuard
from backend.shared.circuit_breaker import CostCircuitBreaker, RateLimiter


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def project_root(tmp_dir):
    """Create a temp project root with test files."""
    os.makedirs(os.path.join(tmp_dir, "config"), exist_ok=True)
    with open(os.path.join(tmp_dir, "config", "db.py"), "w") as f:
        f.write("DB_HOST = 'localhost'\nDB_PORT = 5432\n")
    with open(os.path.join(tmp_dir, "app.log"), "w") as f:
        f.write("INFO: Server started\n")
    return tmp_dir


@pytest.fixture
def security_config(project_root):
    return SecurityConfig(
        mode=SentryMode.AUDIT,
        stop_file_path=os.path.join(project_root, "STOP_SENTRY"),
        project_root=project_root,
    )


@pytest.fixture
def active_security_config(project_root):
    return SecurityConfig(
        mode=SentryMode.ACTIVE,
        stop_file_path=os.path.join(project_root, "STOP_SENTRY"),
        project_root=project_root,
    )


@pytest.fixture
def security_guard(security_config):
    return SecurityGuard(security_config)


@pytest.fixture
def active_security_guard(active_security_config):
    return SecurityGuard(active_security_config)


@pytest.fixture
def circuit_breaker():
    return CostCircuitBreaker(max_cost_usd=5.0, window_minutes=10)


@pytest.fixture
def rate_limiter():
    return RateLimiter()


@pytest.fixture
def memory_config(tmp_dir):
    return MemoryConfig(
        file_path=os.path.join(tmp_dir, "data", "test_memory.json"),
        backup_on_write=False,
    )


@pytest.fixture
def app_config(security_config, memory_config):
    return AppConfig(
        security=security_config,
        memory=memory_config,
    )
