"""
JSON-based memory store for incident history.
Implements IMemoryStore with thread-safe, crash-safe file operations.

Writes are atomic: content is written to `<path>.tmp`, fsynced, then
os.replace()d into place. A crash mid-write leaves either the old file
or the new file — never a partial one.

**P3.4 deprecation note.**  The JSON store remains the dev-mode default
(when ``DATABASE_URL`` is empty) and is used by the entire pre-P1.2 test
suite. In production, configure a Postgres ``DATABASE_URL`` and
:class:`backend.persistence.repositories.memory_repo.PostgresMemoryRepo`
takes over automatically — it implements the same :class:`IMemoryStore`
contract. Deleting this module is blocked on migrating the ~25 unit
tests that import it directly; see P3.4b in ``implementation_plan.md``.
"""

import asyncio
import json
import logging
import os
import shutil
from datetime import datetime, timezone
from typing import Optional

from backend.shared.config import MemoryConfig
from backend.shared.interfaces import IMemoryStore
from backend.shared.models import MemoryEntry

logger = logging.getLogger(__name__)


class JSONMemoryStore(IMemoryStore):
    """Persistent JSON-based memory store with atomic writes."""

    def __init__(self, config: MemoryConfig):
        self._config = config
        self._lock = asyncio.Lock()
        self._ensure_file_exists()

    def _ensure_file_exists(self) -> None:
        os.makedirs(os.path.dirname(self._config.file_path), exist_ok=True)
        if not os.path.exists(self._config.file_path):
            self._write_raw({"system_fingerprint": "", "incident_history": []})

    def _read_raw(self) -> dict:
        try:
            with open(self._config.file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {"system_fingerprint": "", "incident_history": []}

    def _write_raw(self, data: dict) -> None:
        """Atomic write: tmp + fsync + os.replace.

        Crash-safe: if the process is killed mid-write the original file
        is untouched. The .tmp file may be left behind but is reclaimed
        on the next successful write.
        """
        if self._config.backup_on_write and os.path.exists(self._config.file_path):
            try:
                shutil.copy2(self._config.file_path, self._config.file_path + ".bak")
            except OSError as e:  # pragma: no cover
                logger.warning(f"Backup failed: {e}")

        tmp_path = self._config.file_path + ".tmp"
        payload = json.dumps(data, indent=2)
        # Write to tmp, fsync the data + directory, then atomically rename.
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:  # pragma: no cover (Windows file-sync quirks)
                pass
        os.replace(tmp_path, self._config.file_path)
        # Best-effort directory fsync on POSIX to persist the rename.
        try:  # pragma: no cover (POSIX-only)
            dir_fd = os.open(os.path.dirname(self._config.file_path), os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except (OSError, AttributeError):
            pass

    async def load(self) -> list[MemoryEntry]:
        async with self._lock:
            data = self._read_raw()
            return [
                MemoryEntry.from_dict(item)
                for item in data.get("incident_history", [])
            ]

    async def save(self, entry: MemoryEntry) -> None:
        async with self._lock:
            data = self._read_raw()
            entry_dict = entry.to_dict()
            if not entry_dict.get("timestamp"):
                entry_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
            data.setdefault("incident_history", []).append(entry_dict)
            self._write_raw(data)
            logger.info(f"Memory saved: {entry.id}")

    async def get_relevant(self, vectors: list[str]) -> list[MemoryEntry]:
        entries = await self.load()
        relevant = []
        for entry in entries:
            overlap = set(entry.vectors) & set(vectors)
            if overlap:
                relevant.append(entry)
        return sorted(relevant, key=lambda e: len(set(e.vectors) & set(vectors)), reverse=True)

    async def get_count(self) -> int:
        entries = await self.load()
        return len(entries)

    async def compact(self, summary_entries: list[MemoryEntry]) -> None:
        async with self._lock:
            data = self._read_raw()
            data["incident_history"] = [e.to_dict() for e in summary_entries]
            self._write_raw(data)
            logger.info(f"Memory compacted to {len(summary_entries)} entries")

    async def set_fingerprint(self, fingerprint: str) -> None:
        async with self._lock:
            data = self._read_raw()
            data["system_fingerprint"] = fingerprint
            self._write_raw(data)

    async def get_fingerprint(self) -> str:
        async with self._lock:
            data = self._read_raw()
            return data.get("system_fingerprint", "")
