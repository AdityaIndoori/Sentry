"""
Service Registry — builds service context from .env configuration.

No YAML files needed. The user provides two paths in .env:
  - SERVICE_SOURCE_PATH: path to the service's source code
  - WATCH_PATHS: comma-separated log file paths/globs

The AI agents then use read_file and grep_search tools to explore the source code
and understand the service architecture at runtime.
"""

import logging
import os

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
        """Build the prompt context string for agent injection, including file tree."""
        if not self._context.has_context():
            return ""
        base_prompt = self._context.build_prompt()
        file_tree = self._scan_file_tree()
        if file_tree:
            base_prompt = base_prompt.replace(
                "=== END SERVICE CONTEXT ===",
                f"\n--- FILE TREE (files available via read_file) ---\n"
                f"{file_tree}\n"
                f"--- END FILE TREE ---\n\n"
                f"CRITICAL: Use ONLY the paths listed above when calling read_file or "
                f"grep_search. Paths are RELATIVE to the source root — do NOT add any "
                f"prefix like 'shop/' or 'src/' that is not shown in the tree.\n"
                f"=== END SERVICE CONTEXT ==="
            )
        return base_prompt

    def _scan_file_tree(self, max_files: int = 200) -> str:
        """Scan the source directory and return a compact file listing."""
        source = self._context.source_path
        if not source or not os.path.isdir(source):
            return ""
        lines = []
        count = 0
        skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv",
                     ".mypy_cache", ".pytest_cache", "htmlcov", ".tox"}
        for root, dirs, files in os.walk(source):
            # Skip hidden/cache directories
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
            for fname in sorted(files):
                if count >= max_files:
                    lines.append(f"  ... (truncated at {max_files} files)")
                    return "\n".join(lines)
                rel = os.path.relpath(os.path.join(root, fname), source)
                # Normalize to forward slashes for the LLM
                rel = rel.replace("\\", "/")
                lines.append(f"  {rel}")
                count += 1
        if not lines:
            return ""
        return "\n".join(lines)

    def build_fingerprint(self) -> str:
        """Build system fingerprint for the memory store."""
        return self._context.build_fingerprint()
