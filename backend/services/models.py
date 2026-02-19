"""
Service context — minimal model for service awareness.

Sentry learns about the monitored service by reading its source code
and logs at runtime. The user only provides two paths in .env:
  - SERVICE_SOURCE_PATH: where the service source code lives
  - WATCH_PATHS: where the service logs are

The AI agents use read_file and grep_search tools to explore the source code
themselves — no manual YAML documentation required.
"""

from dataclasses import dataclass, field


@dataclass
class ServiceContext:
    """
    Lightweight context about the monitored service.
    
    Built automatically from .env paths — no YAML needed.
    Agents receive this as part of their prompts so they know
    WHERE to look, then they figure out HOW the service works
    by reading the actual source code.
    """
    source_path: str = ""        # Path to the service's source code
    log_paths: list[str] = field(default_factory=list)  # Watched log file paths

    def build_prompt(self) -> str:
        """
        Generate the service context block injected into agent prompts.
        Tells agents where to find the source code and logs, and
        instructs them to read the code to understand the service.
        """
        parts = [
            "=== SERVICE CONTEXT ===",
            f"Source code path: {self.source_path}" if self.source_path else "",
        ]
        if self.log_paths:
            parts.append(f"Log file paths: {', '.join(self.log_paths)}")
        parts.append("")
        parts.append(
            "IMPORTANT: You have access to the service's source code via the read_file "
            "and grep_search tools. Use them to understand how the service works — "
            "read config files, entry points, error handlers, and dependencies. "
            "The source code is the ground truth for understanding this service."
        )
        parts.append("=== END SERVICE CONTEXT ===")
        return "\n".join(p for p in parts if p is not None)

    def has_context(self) -> bool:
        """Return True if we have at least a source path or log paths."""
        return bool(self.source_path) or bool(self.log_paths)

    def build_fingerprint(self) -> str:
        """Build a simple system fingerprint for the memory store."""
        lines = ["Monitored Service:"]
        if self.source_path:
            lines.append(f"  Source: {self.source_path}")
        if self.log_paths:
            lines.append(f"  Logs: {', '.join(self.log_paths)}")
        return "\n".join(lines)
