"""
Abstract interfaces (Ports) for Sentry.
Following Dependency Inversion Principle - depend on abstractions, not concretions.
"""

from abc import ABC, abstractmethod
from typing import AsyncIterator, Optional

from .models import (
    Incident,
    LogEvent,
    MemoryEntry,
    ToolCall,
    ToolResult,
)


class ILogWatcher(ABC):
    """Interface for log file monitoring."""

    @abstractmethod
    async def start(self) -> None:
        """Start watching log files."""

    @abstractmethod
    async def stop(self) -> None:
        """Stop watching log files."""

    @abstractmethod
    async def events(self) -> AsyncIterator[LogEvent]:
        """Yield log events as they are detected."""


class ILLMClient(ABC):
    """Interface for LLM communication (Anthropic Opus)."""

    @abstractmethod
    async def analyze(
        self,
        prompt: str,
        effort: str = "low",
        tools: Optional[list] = None,
    ) -> dict:
        """Send analysis request to LLM and return response."""

    @abstractmethod
    async def get_usage(self) -> dict:
        """Return current token usage statistics."""


class IToolExecutor(ABC):
    """Interface for MCP tool execution."""

    @abstractmethod
    async def execute(self, tool_call: ToolCall) -> ToolResult:
        """Execute a tool call and return the result."""

    @abstractmethod
    def get_tool_definitions(self) -> list:
        """Return all tool definitions for LLM context."""

    @abstractmethod
    def get_read_only_tool_definitions(self) -> list:
        """Return only read-only tool definitions (no apply_patch, restart_service).
        
        Used by the Diagnosis agent which must investigate but never modify.
        """

    @abstractmethod
    def get_remediation_tool_definitions(self) -> list:
        """Return tools for the Remediation agent: read_file + active tools.
        
        Excludes grep_search, fetch_docs, run_diagnostics to prevent the LLM
        from wasting tool loops on investigation instead of applying fixes.
        """


class IMemoryStore(ABC):
    """Interface for persistent incident memory."""

    @abstractmethod
    async def load(self) -> list[MemoryEntry]:
        """Load all memory entries."""

    @abstractmethod
    async def save(self, entry: MemoryEntry) -> None:
        """Save a new memory entry."""

    @abstractmethod
    async def get_relevant(self, vectors: list[str]) -> list[MemoryEntry]:
        """Retrieve entries matching the given vectors."""

    @abstractmethod
    async def get_count(self) -> int:
        """Return total number of stored entries."""

    @abstractmethod
    async def compact(self, summary_entries: list[MemoryEntry]) -> None:
        """Replace all entries with compacted summaries."""


class INotifier(ABC):
    """Interface for human notification (Slack, PagerDuty, etc.)."""

    @abstractmethod
    async def send_alert(self, incident: Incident, message: str) -> bool:
        """Send an escalation alert. Returns True if delivered."""

    @abstractmethod
    async def send_resolution(self, incident: Incident) -> bool:
        """Send a resolution notification."""


class IOrchestrator(ABC):
    """Interface for the core orchestration engine."""

    @abstractmethod
    async def handle_event(self, event: LogEvent) -> Optional[Incident]:
        """Process a log event through the state machine."""

    @abstractmethod
    async def get_active_incidents(self) -> list[Incident]:
        """Return all currently active incidents."""

    @abstractmethod
    async def get_status(self) -> dict:
        """Return current orchestrator status."""
