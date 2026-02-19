"""
Service Registry — builds service context from .env configuration.

No YAML files needed. The user provides two paths in .env:
  - SERVICE_SOURCE_PATH: path to the service's source code
  - WATCH_PATHS: comma-separated log file paths/globs

The AI agents then use read_file and grep_search to explore the source code
and understand the service architecture at runtime.
"""

import logging

from backend.services.models import ServiceContext
from backend.shared.config import AppConfig

logger = logging.getLogger(__name__)


class ServiceRegistry:
    """
    Builds ServiceContext from AppConfig.
    
    This is deliberately simple — the intelligence lives in the AI agents,
    not in manual configuration files. The registry just tells agents
    WHERE to look; they figure out the rest by reading the code.
    """

    def __init__(self, config: AppConfig):
        self._context = ServiceContext(
            source_path=config.service_source_path,
            log_paths=list(config.watcher.watch_paths),
        )
        if self._context.has_context():
            logger.info(
                f"Service awareness active — source: {self._context.source_path}, "
                f"logs: {', '.join(self._context.log_paths)}"
            )
        else:
            logger.warning("No service paths configured — agents will operate without service context")

    @property
    def context(self) -> ServiceContext:
        """Get the service context."""
        return self._context

    def has_context(self) -> bool:
        """Check if service context is available."""
        return self._context.has_context()

    def build_prompt_context(self) -> str:
        """Build the prompt context string for agent injection."""
        if not self._context.has_context():
            return ""
        return self._context.build_prompt()

    def build_fingerprint(self) -> str:
        """Build system fingerprint for the memory store."""
        return self._context.build_fingerprint()
