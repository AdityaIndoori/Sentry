"""
Immutable Audit Log - Tamper-proof logging for forensic analysis.

All agent reasoning steps (Chain of Thought) and final actions are
logged to a hash-chained JSONL file. Each entry includes the SHA-256
hash of the previous entry, making tampering detectable.

Zero Trust principle: Log everything, trust nothing, verify integrity.
"""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

logger = logging.getLogger(__name__)


class ImmutableAuditLog:
    """
    Append-only, hash-chained audit log.

    Each entry is a JSON line containing:
    - timestamp, agent_id, action, detail, result
    - chain_of_thought (optional - for reasoning transparency)
    - prev_hash (SHA-256 of previous entry for tamper detection)
    - entry_hash (SHA-256 of this entry for chain verification)

    Format: JSONL (one JSON object per line)
    """

    def __init__(self, log_path: str):
        self._log_path = log_path
        self._lock = Lock()
        self._last_hash = "genesis"

        # Ensure directory exists
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        # Recover last hash from existing log
        if os.path.exists(log_path):
            self._recover_last_hash()

    def log_action(
        self,
        agent_id: str,
        action: str,
        detail: str,
        result: str,
        chain_of_thought: str = "",
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Append an immutable entry to the audit log.
        Returns the entry hash.
        """
        with self._lock:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent_id,
                "action": action,
                "detail": detail,
                "result": result,
                "chain_of_thought": chain_of_thought,
                "metadata": metadata or {},
                "prev_hash": self._last_hash,
            }

            # Compute hash of this entry (without entry_hash field)
            entry_str = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            entry_hash = hashlib.sha256(entry_str.encode()).hexdigest()
            entry["entry_hash"] = entry_hash

            # Append to file
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":")) + "\n")

            self._last_hash = entry_hash
            return entry_hash

    def read_all(self) -> list[dict]:
        """Read all audit log entries."""
        if not os.path.exists(self._log_path):
            return []

        entries = []
        with open(self._log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.error(f"Corrupt audit log line: {line[:100]}")
        return entries

    def verify_integrity(self) -> bool:
        """
        Verify the hash chain integrity of the entire log.
        Returns True if all entries are consistent (no tampering).
        """
        entries = self.read_all()
        if not entries:
            return True

        prev_hash = "genesis"
        for i, entry in enumerate(entries):
            # Check prev_hash matches
            if entry.get("prev_hash") != prev_hash:
                logger.error(
                    f"INTEGRITY VIOLATION at entry {i}: "
                    f"expected prev_hash={prev_hash}, "
                    f"got {entry.get('prev_hash')}"
                )
                return False

            # Recompute hash of entry (without entry_hash)
            stored_hash = entry.pop("entry_hash", "")
            entry_str = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            computed_hash = hashlib.sha256(entry_str.encode()).hexdigest()
            entry["entry_hash"] = stored_hash  # Restore

            if computed_hash != stored_hash:
                logger.error(
                    f"INTEGRITY VIOLATION at entry {i}: "
                    f"hash mismatch (computed={computed_hash[:16]}..., "
                    f"stored={stored_hash[:16]}...)"
                )
                return False

            prev_hash = stored_hash

        return True

    def get_entry_count(self) -> int:
        """Return the number of entries in the log."""
        return len(self.read_all())

    def _recover_last_hash(self) -> None:
        """Recover the last hash from an existing log file."""
        entries = self.read_all()
        if entries:
            self._last_hash = entries[-1].get("entry_hash", "genesis")
