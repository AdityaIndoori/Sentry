"""
Log watcher - monitors log files for error patterns.
Uses polling to support Docker volumes and remote mounts.
"""

import asyncio
import glob
import logging
import os
import re
from datetime import datetime
from typing import AsyncIterator, Callable, Optional

from backend.shared.config import WatcherConfig
from backend.shared.models import LogEvent

logger = logging.getLogger(__name__)


class LogWatcher:
    """Polls log files for error patterns and emits LogEvents."""

    def __init__(self, config: WatcherConfig):
        self._config = config
        self._patterns = [re.compile(p) for p in config.error_patterns]
        self._running = False
        self._file_positions: dict[str, int] = {}
        self._event_queue: asyncio.Queue[LogEvent] = asyncio.Queue(maxsize=100)

    async def start(self) -> None:
        """Start the polling loop."""
        self._running = True
        logger.info(f"Watcher started. Paths: {self._config.watch_paths}")
        asyncio.create_task(self._poll_loop())

    async def stop(self) -> None:
        """Stop the polling loop."""
        self._running = False
        logger.info("Watcher stopped")

    async def events(self) -> AsyncIterator[LogEvent]:
        """Yield events from the queue."""
        while self._running or not self._event_queue.empty():
            try:
                event = await asyncio.wait_for(
                    self._event_queue.get(), timeout=1.0
                )
                yield event
            except asyncio.TimeoutError:
                continue

    async def _poll_loop(self) -> None:
        """Main polling loop."""
        while self._running:
            try:
                files = self._resolve_paths()
                for fpath in files:
                    await self._check_file(fpath)
            except Exception as e:
                logger.error(f"Watcher poll error: {e}")
            await asyncio.sleep(self._config.poll_interval_seconds)

    def _resolve_paths(self) -> list[str]:
        """Resolve glob patterns to actual file paths."""
        files = []
        for pattern in self._config.watch_paths:
            files.extend(glob.glob(pattern))
        return files

    async def _check_file(self, path: str) -> None:
        """Check a single file for new error lines."""
        try:
            size = os.path.getsize(path)
            last_pos = self._file_positions.get(path, 0)

            # File was truncated/rotated
            if size < last_pos:
                last_pos = 0

            if size == last_pos:
                return

            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(last_pos)
                line_num = sum(1 for _ in open(path, "rb")) if last_pos == 0 else 0

                for line in f:
                    line_num += 1
                    for pattern in self._patterns:
                        if pattern.search(line):
                            event = LogEvent(
                                source_file=path,
                                line_content=line.strip()[:500],
                                timestamp=datetime.utcnow(),
                                matched_pattern=pattern.pattern,
                                line_number=line_num,
                            )
                            try:
                                self._event_queue.put_nowait(event)
                            except asyncio.QueueFull:
                                logger.warning("Event queue full, dropping event")
                            break  # One match per line

                self._file_positions[path] = f.tell()
        except (OSError, PermissionError) as e:
            logger.debug(f"Cannot read {path}: {e}")

    async def inject_event(self, event: LogEvent) -> None:
        """Manually inject an event (for testing/API triggers)."""
        await self._event_queue.put(event)
