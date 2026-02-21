"""
Tests for watcher/log_watcher.py — log file monitoring.
"""

import asyncio
import os
import pytest
from datetime import datetime, timezone

from backend.shared.config import WatcherConfig
from backend.shared.models import LogEvent
from backend.watcher.log_watcher import LogWatcher


class TestLogWatcherInit:
    def test_initializes_with_config(self):
        config = WatcherConfig(
            watch_paths=("/var/log/test.log",),
            poll_interval_seconds=1.0,
        )
        watcher = LogWatcher(config)
        assert watcher._running is False
        assert len(watcher._patterns) > 0

    def test_patterns_compiled(self):
        config = WatcherConfig(error_patterns=(r"error", r"critical"))
        watcher = LogWatcher(config)
        assert len(watcher._patterns) == 2


class TestLogWatcherStartStop:
    @pytest.mark.asyncio
    async def test_start_sets_running(self):
        config = WatcherConfig(watch_paths=())
        watcher = LogWatcher(config)
        await watcher.start()
        assert watcher._running is True
        await watcher.stop()

    @pytest.mark.asyncio
    async def test_stop_clears_running(self):
        config = WatcherConfig(watch_paths=())
        watcher = LogWatcher(config)
        await watcher.start()
        await watcher.stop()
        assert watcher._running is False


class TestLogWatcherResolvePaths:
    def test_resolves_glob_pattern(self, tmp_dir):
        # Create a test log file
        log_file = os.path.join(tmp_dir, "test.log")
        with open(log_file, "w") as f:
            f.write("test\n")

        config = WatcherConfig(
            watch_paths=(os.path.join(tmp_dir, "*.log"),),
        )
        watcher = LogWatcher(config)
        paths = watcher._resolve_paths()
        assert log_file in paths

    def test_no_matches_returns_empty(self, tmp_dir):
        config = WatcherConfig(
            watch_paths=(os.path.join(tmp_dir, "nonexistent*.xyz"),),
        )
        watcher = LogWatcher(config)
        paths = watcher._resolve_paths()
        assert paths == []


class TestLogWatcherCheckFile:
    @pytest.mark.asyncio
    async def test_detects_error_in_new_file(self, tmp_dir):
        log_file = os.path.join(tmp_dir, "app.log")
        with open(log_file, "w") as f:
            f.write("INFO: Server started\n")
            f.write("ERROR: Connection refused on port 3000\n")
            f.write("INFO: Retrying...\n")

        config = WatcherConfig(
            watch_paths=(log_file,),
            error_patterns=(r"(?i)error",),
        )
        watcher = LogWatcher(config)
        await watcher._check_file(log_file)

        # Should have detected the ERROR line
        assert not watcher._event_queue.empty()
        event = await watcher._event_queue.get()
        assert "Connection refused" in event.line_content
        assert event.source_file == log_file

    @pytest.mark.asyncio
    async def test_tracks_file_position(self, tmp_dir):
        log_file = os.path.join(tmp_dir, "app.log")
        with open(log_file, "w") as f:
            f.write("ERROR: first error\n")

        config = WatcherConfig(
            watch_paths=(log_file,),
            error_patterns=(r"(?i)error",),
        )
        watcher = LogWatcher(config)
        await watcher._check_file(log_file)

        # First check should find the error
        assert not watcher._event_queue.empty()
        await watcher._event_queue.get()

        # Second check with no new content should find nothing
        await watcher._check_file(log_file)
        assert watcher._event_queue.empty()

    @pytest.mark.asyncio
    async def test_detects_new_lines_after_append(self, tmp_dir):
        log_file = os.path.join(tmp_dir, "app.log")
        with open(log_file, "w") as f:
            f.write("INFO: normal\n")

        config = WatcherConfig(
            watch_paths=(log_file,),
            error_patterns=(r"(?i)error",),
        )
        watcher = LogWatcher(config)
        await watcher._check_file(log_file)

        # No errors yet
        assert watcher._event_queue.empty()

        # Append an error
        with open(log_file, "a") as f:
            f.write("ERROR: new error\n")

        await watcher._check_file(log_file)
        assert not watcher._event_queue.empty()
        event = await watcher._event_queue.get()
        assert "new error" in event.line_content

    @pytest.mark.asyncio
    async def test_handles_file_rotation(self, tmp_dir):
        log_file = os.path.join(tmp_dir, "app.log")
        with open(log_file, "w") as f:
            f.write("ERROR: old error\n" * 10)

        config = WatcherConfig(
            watch_paths=(log_file,),
            error_patterns=(r"(?i)error",),
        )
        watcher = LogWatcher(config)
        await watcher._check_file(log_file)

        # Drain the queue
        while not watcher._event_queue.empty():
            await watcher._event_queue.get()

        # Simulate log rotation (file gets smaller)
        with open(log_file, "w") as f:
            f.write("ERROR: after rotation\n")

        await watcher._check_file(log_file)
        assert not watcher._event_queue.empty()

    @pytest.mark.asyncio
    async def test_handles_missing_file(self, tmp_dir):
        config = WatcherConfig(
            watch_paths=(os.path.join(tmp_dir, "missing.log"),),
            error_patterns=(r"(?i)error",),
        )
        watcher = LogWatcher(config)
        # Should not raise
        await watcher._check_file(os.path.join(tmp_dir, "missing.log"))
        assert watcher._event_queue.empty()


class TestLogWatcherQueueFull:
    @pytest.mark.asyncio
    async def test_queue_full_drops_event(self, tmp_dir):
        """When event queue is full, new events are dropped gracefully."""
        log_file = os.path.join(tmp_dir, "app.log")
        # Write more error lines than the queue can hold (maxsize=100)
        with open(log_file, "w") as f:
            for i in range(120):
                f.write(f"ERROR: error number {i}\n")

        config = WatcherConfig(
            watch_paths=(log_file,),
            error_patterns=(r"(?i)error",),
        )
        watcher = LogWatcher(config)
        await watcher._check_file(log_file)

        # Queue should be full at 100, remaining 20 dropped
        assert watcher._event_queue.qsize() == 100


class TestLogWatcherPermissionError:
    @pytest.mark.asyncio
    async def test_handles_permission_error(self, tmp_dir):
        """PermissionError on file read should be handled gracefully."""
        log_file = os.path.join(tmp_dir, "protected.log")
        with open(log_file, "w") as f:
            f.write("ERROR: secret\n")

        config = WatcherConfig(
            watch_paths=(log_file,),
            error_patterns=(r"(?i)error",),
        )
        watcher = LogWatcher(config)

        # Make file unreadable by patching open to raise PermissionError
        from unittest.mock import patch, mock_open
        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            # os.path.getsize still works, but open fails
            await watcher._check_file(log_file)

        # Should not crash, queue should be empty
        assert watcher._event_queue.empty()


class TestLogWatcherInjectEvent:
    @pytest.mark.asyncio
    async def test_inject_event(self):
        config = WatcherConfig(watch_paths=())
        watcher = LogWatcher(config)
        event = LogEvent(
            source_file="manual",
            line_content="Injected error",
        )
        await watcher.inject_event(event)
        assert not watcher._event_queue.empty()
        retrieved = await watcher._event_queue.get()
        assert retrieved.line_content == "Injected error"
