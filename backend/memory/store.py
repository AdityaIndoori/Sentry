"""
JSON-based memory store for incident history.
Implements IMemoryStore with thread-safe file operations.
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
    """Persistent JSON-based memory store."""

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
            with open(self._config.file_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {"system_fingerprint": "", "incident_history": []}

    def _write_raw(self, data: dict) -> None:
        if self._config.backup_on_write and os.path.exists(self._config.file_path):
            shutil.copy2(self._config.file_path, self._config.file_path + ".bak")
        with open(self._config.file_path, "w") as f:
            json.dump(data, f, indent=2)

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
