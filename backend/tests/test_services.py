"""
Tests for services.models.ServiceContext and services.registry.ServiceRegistry.
"""

import pytest
from backend.services.models import ServiceContext
from backend.services.registry import ServiceRegistry
from backend.shared.config import AppConfig, SecurityConfig, WatcherConfig, MemoryConfig


class TestServiceContext:
    def test_default_empty(self):
        ctx = ServiceContext()
        assert ctx.source_path == ""
        assert ctx.log_paths == []

    def test_has_context_with_source(self):
        ctx = ServiceContext(source_path="/app/src")
        assert ctx.has_context() is True

    def test_has_context_with_logs(self):
        ctx = ServiceContext(log_paths=["/var/log/app.log"])
        assert ctx.has_context() is True

    def test_has_context_empty(self):
        ctx = ServiceContext()
        assert ctx.has_context() is False

    def test_build_prompt_with_source(self):
        ctx = ServiceContext(source_path="/app/src", log_paths=["/var/log/app.log"])
        prompt = ctx.build_prompt()
        assert "SERVICE CONTEXT" in prompt
        assert "/app/src" in prompt
        assert "/var/log/app.log" in prompt
        assert "read_file" in prompt
        assert "grep_search" in prompt

    def test_build_prompt_no_source(self):
        ctx = ServiceContext(log_paths=["/var/log/app.log"])
        prompt = ctx.build_prompt()
        assert "SERVICE CONTEXT" in prompt
        assert "/var/log/app.log" in prompt

    def test_build_prompt_empty(self):
        ctx = ServiceContext()
        prompt = ctx.build_prompt()
        assert "SERVICE CONTEXT" in prompt

    def test_build_fingerprint_with_source(self):
        ctx = ServiceContext(source_path="/app/src", log_paths=["/var/log/a.log"])
        fp = ctx.build_fingerprint()
        assert "Source: /app/src" in fp
        assert "Logs:" in fp

    def test_build_fingerprint_empty(self):
        ctx = ServiceContext()
        fp = ctx.build_fingerprint()
        assert "Monitored Service:" in fp


class TestServiceRegistry:
    def test_init_with_context(self):
        config = AppConfig(
            service_source_path="/app/src",
            watcher=WatcherConfig(watch_paths=("/var/log/app.log",)),
        )
        registry = ServiceRegistry(config)
        assert registry.has_context() is True
        assert registry.context.source_path == "/app/src"

    def test_init_without_context(self):
        config = AppConfig(
            service_source_path="",
            watcher=WatcherConfig(watch_paths=()),
        )
        registry = ServiceRegistry(config)
        assert registry.has_context() is False

    def test_build_prompt_context_with_context(self):
        config = AppConfig(
            service_source_path="/app/src",
            watcher=WatcherConfig(watch_paths=("/var/log/app.log",)),
        )
        registry = ServiceRegistry(config)
        prompt = registry.build_prompt_context()
        assert "SERVICE CONTEXT" in prompt

    def test_build_prompt_context_without_context(self):
        config = AppConfig(
            service_source_path="",
            watcher=WatcherConfig(watch_paths=()),
        )
        registry = ServiceRegistry(config)
        prompt = registry.build_prompt_context()
        assert prompt == ""

    def test_build_fingerprint(self):
        config = AppConfig(
            service_source_path="/app/src",
            watcher=WatcherConfig(watch_paths=("/var/log/app.log",)),
        )
        registry = ServiceRegistry(config)
        fp = registry.build_fingerprint()
        assert "Monitored Service:" in fp
