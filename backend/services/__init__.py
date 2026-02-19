"""
Service Awareness Layer for Sentry.

The user provides two paths in .env:
  - SERVICE_SOURCE_PATH: path to the service's source code
  - WATCH_PATHS: comma-separated log file paths

The AI agents use read_file and grep_search tools to explore the source code
and understand the service architecture at runtime — no YAML needed.
"""

from backend.services.models import ServiceContext
from backend.services.registry import ServiceRegistry

__all__ = [
    "ServiceContext",
    "ServiceRegistry",
]
