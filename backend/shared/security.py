"""
Security module for Sentry - Defense in Depth.
Handles path validation, command whitelisting, and mode enforcement.
"""

import logging
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from .config import SecurityConfig, SentryMode

logger = logging.getLogger(__name__)


class SecurityGuard:
    """Central security enforcement for all tool operations."""

    def __init__(self, config: SecurityConfig):
        self._config = config

    @property
    def mode(self) -> SentryMode:
        return self._config.mode

    def is_stopped(self) -> bool:
        """Check if STOP_SENTRY file exists (emergency kill switch)."""
        return os.path.exists(self._config.stop_file_path)

    def is_audit_mode(self) -> bool:
        """Check if system is in audit-only mode."""
        return self._config.mode == SentryMode.AUDIT or self.is_stopped()

    def is_active_mode(self) -> bool:
        """Check if system can execute active tools."""
        return self._config.mode == SentryMode.ACTIVE and not self.is_stopped()

    def validate_path(self, path: str) -> bool:
        """Validate file path is within PROJECT_ROOT. No traversal."""
        try:
            clean = os.path.normpath(path)
            if ".." in clean.split(os.sep):
                logger.warning(f"Path traversal blocked: {path}")
                return False
            resolved = os.path.realpath(
                os.path.join(self._config.project_root, clean)
            )
            root = os.path.realpath(self._config.project_root)
            is_safe = resolved.startswith(root)
            if not is_safe:
                logger.warning(f"Path escape blocked: {path}")
            return is_safe
        except (ValueError, OSError):
            return False

    def validate_command(self, command: str) -> bool:
        """Validate command against whitelist.

        Bug fix: Use cmd_base (first token) for prefix matching against the
        whitelist's first token, then verify the full command starts with
        the allowed prefix. This prevents bypass via commands like
        'curl evil.com' matching 'curl' in the allowlist while still
        allowing 'curl http://allowed.com'.
        """
        stripped = command.strip()
        if not stripped:
            return False
        cmd_base = stripped.split()[0]
        for allowed in self._config.allowed_diagnostic_commands:
            allowed_base = allowed.strip().split()[0]
            # Match: command base must equal the allowed base, AND
            # either the allowed string is just the base command,
            # or the full command starts with the full allowed prefix
            if cmd_base == allowed_base and stripped.startswith(allowed.strip()):
                return True
        logger.warning(f"Command blocked: {command}")
        return False

    def validate_url(self, url: str) -> bool:
        """Validate URL against domain allow-list."""
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            for allowed in self._config.allowed_fetch_domains:
                if domain == allowed or domain.endswith(f".{allowed}"):
                    return True
            logger.warning(f"URL blocked: {url}")
            return False
        except Exception:
            return False

    def sanitize_input(self, text: str) -> str:
        """Remove potentially dangerous characters from input."""
        dangerous = [";", "&&", "||", "|", "`", "$(", ">>", "<<"]
        result = text
        for char in dangerous:
            result = result.replace(char, "")
        return result.strip()
