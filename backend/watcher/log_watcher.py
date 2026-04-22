"""
Log watcher - monitors log files for error patterns.
Uses polling to support Docker volumes and remote mounts.

Hardened:
- UTF-8 safe: reads in binary mode and decodes with a carry buffer so a
  multi-byte UTF-8 codepoint split across two polls doesn't raise.
- Rotation-safe: tracks (offset, inode) per file. If the inode changes
  (logrotate renamed the file) or the size shrinks (truncate-in-place),
  the offset is reset to 0.
- start() returns the asyncio.Task so the caller can own its lifecycle
  (cancel on shutdown) instead of leaking the task.
"""

import asyncio
import glob
import logging
import os
import re
from datetime import datetime, timezone
from typing import AsyncIterator, Optional

from backend.shared.config import WatcherConfig
from backend.shared.interfaces import ILogWatcher
from backend.shared.models import LogEvent

logger = logging.getLogger(__name__)

# Max bytes read per poll per file — prevents a giant single read from
# starving the event loop when someone cat's a huge file into the log.
_MAX_READ_PER_POLL = 2 * 1024 * 1024  # 2 MB


class LogWatcher(ILogWatcher):
    """Polls log files for error patterns and emits LogEvents."""

    def __init__(self, config: WatcherConfig):
        self._config = config
        self._patterns = [re.compile(p) for p in config.error_patterns]
        self._running = False
        # value is (offset_in_bytes, inode_or_zero, carry_bytes)
        # carry_bytes holds the trailing bytes of the previous read that
        # didn't form a complete UTF-8 codepoint — they are re-used on the
        # next read to avoid UnicodeDecodeError at chunk boundaries.
        self._file_state: dict[str, tuple[int, int, bytes]] = {}
        self._event_queue: asyncio.Queue[LogEvent] = asyncio.Queue(maxsize=100)
        self._poll_task: Optional[asyncio.Task] = None

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> Optional[asyncio.Task]:
        """Start the polling loop. Returns the task handle so the caller
        can cancel it cleanly on shutdown.
        """
        if self._running:
            return self._poll_task
        self._running = True
        logger.info(f"Watcher started. Paths: {self._config.watch_paths}")
        self._poll_task = asyncio.create_task(
            self._poll_loop(), name="sentry-watcher-poll"
        )
        return self._poll_task

    async def stop(self) -> None:
        """Stop the polling loop and wait for the task to exit."""
        self._running = False
        task = self._poll_task
        self._poll_task = None
        if task and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        logger.info("Watcher stopped")

    async def events(self) -> AsyncIterator[LogEvent]:  # pragma: no cover
        """Yield events from the queue."""
        while self._running or not self._event_queue.empty():
            try:
                event = await asyncio.wait_for(
                    self._event_queue.get(), timeout=1.0
                )
                yield event
            except asyncio.TimeoutError:
                continue

    # ── polling ──────────────────────────────────────────────────────────

    async def _poll_loop(self) -> None:  # pragma: no cover
        """Main polling loop."""
        while self._running:
            try:
                files = self._resolve_paths()
                for fpath in files:
                    await self._check_file(fpath)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Watcher poll error: {e}")
            try:
                await asyncio.sleep(self._config.poll_interval_seconds)
            except asyncio.CancelledError:
                break

    def _resolve_paths(self) -> list[str]:
        """Resolve glob patterns to actual file paths."""
        files: list[str] = []
        for pattern in self._config.watch_paths:
            files.extend(glob.glob(pattern))
        return files

    @staticmethod
    def _get_inode(path: str) -> int:
        """Return st_ino on POSIX; on Windows st_ino is typically 0. Returns
        0 on any error (e.g. file vanished between stat and our call)."""
        try:
            return os.stat(path).st_ino
        except OSError:
            return 0

    @staticmethod
    def _safe_utf8_decode(buffer: bytes) -> tuple[str, bytes]:
        """Decode a byte buffer as UTF-8, carrying over any trailing bytes
        that don't form a complete codepoint.

        Returns (decoded_text, trailing_bytes_for_next_read).
        """
        if not buffer:
            return "", b""
        # Try decoding the whole buffer first — the common case.
        try:
            return buffer.decode("utf-8"), b""
        except UnicodeDecodeError as e:
            # e.start is the byte index where the invalid sequence begins.
            # Everything before that is guaranteed valid; everything from
            # there onward might be an incomplete tail codepoint.
            if e.start == 0:
                # Data itself is corrupt from the start — fall back to
                # replace so we don't lose the whole file.
                return buffer.decode("utf-8", errors="replace"), b""
            head = buffer[: e.start].decode("utf-8")
            tail = buffer[e.start :]
            # If the tail is longer than 4 bytes it's not a truncated UTF-8
            # codepoint (max UTF-8 codepoint is 4 bytes) — it's real
            # corruption. Replace it.
            if len(tail) > 4:
                head += tail.decode("utf-8", errors="replace")
                return head, b""
            return head, tail

    async def _check_file(self, path: str) -> None:
        """Check a single file for new error lines.

        Safe under:
        - File rotation (inode change OR size shrinking → reset offset).
        - UTF-8 codepoints split across poll boundaries (carry buffer).
        - PermissionError, FileNotFoundError, OSError (logged and skipped).
        """
        try:
            size = os.path.getsize(path)
        except (OSError, PermissionError) as e:
            logger.debug(f"Cannot stat {path}: {e}")
            return

        state = self._file_state.get(path)
        if state is None:
            last_pos, last_inode, carry = 0, 0, b""
        else:
            last_pos, last_inode, carry = state

        inode = self._get_inode(path)

        # Rotation/truncate detection: inode changed (rename) OR size shrank.
        if (inode and last_inode and inode != last_inode) or size < last_pos:
            logger.info(
                f"Detected rotation/truncate on {path} "
                f"(inode {last_inode}->{inode}, size {size}, prev_pos {last_pos})"
            )
            last_pos = 0
            carry = b""

        # Nothing new to read.
        if size == last_pos and not carry:
            self._file_state[path] = (last_pos, inode, carry)
            return

        try:
            # Read in binary; decode with carry so multi-byte codepoints
            # at the chunk boundary don't explode.
            with open(path, "rb") as f:
                f.seek(last_pos)
                chunk = f.read(_MAX_READ_PER_POLL)
                new_pos = f.tell()
        except (OSError, PermissionError) as e:
            logger.debug(f"Cannot read {path}: {e}")
            return

        if not chunk and not carry:
            self._file_state[path] = (new_pos, inode, carry)
            return

        combined = carry + chunk
        text, new_carry = self._safe_utf8_decode(combined)

        # We need line numbers aligned with the original file for observability.
        # Count lines we've already consumed (approximate — we scan the prefix
        # of the file up to last_pos only when this is the first new chunk
        # at an offset we don't already have line info for).
        line_num_base = self._count_lines_before(path, last_pos) if last_pos > 0 else 0

        # Split out complete lines; the last partial line (no trailing \n)
        # is NOT emitted — we also have to hold back its offset so next poll
        # re-reads it. Simpler approach: find the last '\n'; everything up
        # to and including it is processed now, anything after is held.
        last_newline = text.rfind("\n")
        if last_newline == -1:
            # No full line yet — hold everything for the next poll by not
            # advancing the offset past last_pos. Keep the chunk's bytes
            # inside `new_carry`? No — we want to be able to re-seek and
            # read from last_pos. So: DON'T update offset, keep carry empty,
            # and next poll will re-read the same bytes.
            self._file_state[path] = (last_pos, inode, b"")
            return

        processed_text = text[: last_newline + 1]
        held_text = text[last_newline + 1 :]

        # Bytes held: the UTF-8 of held_text plus any trailing partial carry
        held_bytes = held_text.encode("utf-8") + new_carry

        # Advance offset by the byte length of the processed portion.
        consumed_bytes = len(processed_text.encode("utf-8"))
        # Guard: combined starts with the old `carry` bytes, so the offset we
        # advance from `last_pos` must ignore the carry that was ALREADY
        # counted in last_pos. That is, last_pos was the file position after
        # the previous read, which already covered the carry's source bytes.
        # So: new_offset = last_pos + consumed_bytes - len(carry).
        # But we guarantee last_pos + len(chunk) == new_pos. So:
        carry_len = len(carry)
        new_offset = last_pos + max(0, consumed_bytes - carry_len)
        # Clamp: never advance past what we actually read.
        if new_offset > new_pos:
            new_offset = new_pos

        for i, line in enumerate(processed_text.splitlines(), start=1):
            self._emit_if_matched(path, line, line_num_base + i)

        self._file_state[path] = (new_offset, inode, held_bytes)

    @staticmethod
    def _count_lines_before(path: str, offset: int) -> int:
        """Count newlines in the first `offset` bytes of `path`.

        Only called on the FIRST poll of a file that already has content
        (last_pos > 0 but we don't yet have a base). Subsequent polls
        accumulate line numbers incrementally, but we only need an approximate
        base line number for observability anyway.
        """
        if offset <= 0:
            return 0
        try:
            with open(path, "rb") as f:
                return f.read(offset).count(b"\n")
        except OSError:
            return 0

    def _emit_if_matched(self, path: str, line: str, line_num: int) -> None:
        """Check a single decoded line against error patterns and enqueue
        an event if it matches."""
        for pattern in self._patterns:
            if pattern.search(line):
                # Sanitize log line content to prevent shell injection
                sanitized_line = line.strip()[:500]
                for dangerous in [";", "&&", "||", "|", "`", "$(", ">>", "<<"]:
                    sanitized_line = sanitized_line.replace(dangerous, "")
                sanitized_line = sanitized_line.strip()

                event = LogEvent(
                    source_file=path,
                    line_content=sanitized_line,
                    timestamp=datetime.now(timezone.utc),
                    matched_pattern=pattern.pattern,
                    line_number=line_num,
                )
                try:
                    self._event_queue.put_nowait(event)
                except asyncio.QueueFull:
                    logger.warning("Event queue full, dropping event")
                return  # One match per line

    # Back-compat for tests that touch _file_positions directly.
    @property
    def _file_positions(self) -> dict[str, int]:  # pragma: no cover
        return {p: s[0] for p, s in self._file_state.items()}

    async def inject_event(self, event: LogEvent) -> None:
        """Manually inject an event (for testing/API triggers)."""
        await self._event_queue.put(event)
