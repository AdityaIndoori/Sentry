"""
Tests for services.models.ServiceContext and services.registry.ServiceRegistry.
"""

import os
import tempfile

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


class TestServiceRegistryFileTree:
    """Tests for the file tree scanning feature that prevents path hallucination."""

    def test_file_tree_included_in_prompt(self):
        """File tree should be included in the prompt when source dir exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a small file structure
            os.makedirs(os.path.join(tmpdir, "routes"))
            with open(os.path.join(tmpdir, "app.py"), "w") as f:
                f.write("# main app")
            with open(os.path.join(tmpdir, "routes", "products.py"), "w") as f:
                f.write("# products")

            config = AppConfig(
                service_source_path=tmpdir,
                watcher=WatcherConfig(watch_paths=("/var/log/app.log",)),
            )
            registry = ServiceRegistry(config)
            prompt = registry.build_prompt_context()

            assert "FILE TREE" in prompt
            assert "app.py" in prompt
            assert "routes/products.py" in prompt
            assert "CRITICAL" in prompt

    def test_file_tree_no_hallucinated_prefix(self):
        """File tree paths should be relative — no invented prefixes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, "config"))
            with open(os.path.join(tmpdir, "config", "db.py"), "w") as f:
                f.write("DB=1")

            config = AppConfig(
                service_source_path=tmpdir,
                watcher=WatcherConfig(watch_paths=()),
            )
            registry = ServiceRegistry(config)
            prompt = registry.build_prompt_context()

            assert "config/db.py" in prompt
            # Must NOT contain any made-up prefix
            assert "shop/config" not in prompt
            assert "src/config" not in prompt

    def test_file_tree_skips_hidden_dirs(self):
        """__pycache__, .git, etc. should be excluded from the file tree."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, "__pycache__"))
            os.makedirs(os.path.join(tmpdir, ".git"))
            with open(os.path.join(tmpdir, "app.py"), "w") as f:
                f.write("")
            with open(os.path.join(tmpdir, "__pycache__", "app.cpython-312.pyc"), "w") as f:
                f.write("")
            with open(os.path.join(tmpdir, ".git", "HEAD"), "w") as f:
                f.write("")

            config = AppConfig(
                service_source_path=tmpdir,
                watcher=WatcherConfig(watch_paths=()),
            )
            registry = ServiceRegistry(config)
            tree = registry._scan_file_tree()

            assert "app.py" in tree
            assert "__pycache__" not in tree
            assert ".git" not in tree

    def test_file_tree_nonexistent_dir(self):
        """If source dir doesn't exist, file tree should be empty string."""
        config = AppConfig(
            service_source_path="/nonexistent/path/xyz",
            watcher=WatcherConfig(watch_paths=()),
        )
        registry = ServiceRegistry(config)
        tree = registry._scan_file_tree()
        assert tree == ""

    def test_file_tree_truncates_large_dirs(self):
        """File tree should be truncated for very large directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(10):
                with open(os.path.join(tmpdir, f"file_{i}.py"), "w") as f:
                    f.write("")

            config = AppConfig(
                service_source_path=tmpdir,
                watcher=WatcherConfig(watch_paths=()),
            )
            registry = ServiceRegistry(config)
            tree = registry._scan_file_tree(max_files=5)
            assert "truncated" in tree
