"""
Abstract interfaces (Ports) for Sentry.
Following Dependency Inversion Principle - depend on abstractions, not concretions.
"""

from abc import ABC, abstractmethod
from asyncio import Task
from collections.abc import AsyncIterator
from typing import Any, Optional, Protocol, runtime_checkable

from .models import (
    Incident,
    LogEvent,
    MemoryEntry,
    ToolCall,
    ToolResult,
)

# Alias for heterogeneous LLM/tool payloads that still cross ABI boundaries
# as untyped JSON-ish structures. Concrete implementations (``backend.api``,
# ``backend.tools``) use Pydantic models internally; the ABCs here keep the
# signature broad until the downstream callers are migrated.
_JSON = dict[str, Any]



class ILogWatcher(ABC):
    """Interface for log file monitoring."""

    @abstractmethod
    async def start(self) -> Optional["Task[Any]"]:
        """Start watching log files.

        Returns the background poll task so the caller owns its
        lifecycle (and can cancel it cleanly on shutdown). Implementations
        that do not run a background task may return ``None``.
        """

    @abstractmethod
    async def stop(self) -> None:
        """Stop watching log files."""

    # NOTE: ``events`` is declared WITHOUT ``async`` because it is an
    # *async generator* — calling it returns an ``AsyncIterator``
    # directly, it is not a coroutine that must be awaited. This matches
    # the ``async for event in watcher.events():`` idiom used at every
    # call site. See mypy docs:
    # https://mypy.readthedocs.io/en/stable/more_types.html#asynchronous-iterators
    @abstractmethod
    def events(self) -> AsyncIterator[LogEvent]:
        """Yield log events as they are detected."""
        ...



class ILLMClient(ABC):
    """Interface for LLM communication (Anthropic Opus)."""

    @abstractmethod
    async def analyze(
        self,
        prompt: str,
        effort: str = "low",
        tools: list[_JSON] | None = None,
    ) -> _JSON:
        """Send analysis request to LLM and return response."""

    @abstractmethod
    async def get_usage(self) -> _JSON:
        """Return current token usage statistics."""


class IToolExecutor(ABC):
    """Interface for MCP tool execution."""

    @abstractmethod
    async def execute(self, tool_call: ToolCall) -> ToolResult:
        """Execute a tool call and return the result."""

    @abstractmethod
    def get_tool_definitions(self) -> list[_JSON]:
        """Return all tool definitions for LLM context."""

    @abstractmethod
    def get_read_only_tool_definitions(self) -> list[_JSON]:
        """Return only read-only tool definitions (no apply_patch, restart_service).

        Used by the Diagnosis agent which must investigate but never modify.
        """

    @abstractmethod
    def get_remediation_tool_definitions(self) -> list[_JSON]:
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
    async def handle_event(self, event: LogEvent) -> Incident | None:
        """Process a log event through the state machine."""

    @abstractmethod
    async def get_active_incidents(self) -> list[Incident]:
        """Return all currently active incidents."""

    @abstractmethod
    async def get_status(self) -> _JSON:
        """Return current orchestrator status."""


# ── P4.9d ──────────────────────────────────────────────────────────────
#
# Structural port for the hash-chained audit log. Both
# :class:`backend.shared.audit_log.ImmutableAuditLog` (JSONL file
# backend) and :class:`backend.persistence.repositories.audit_repo.PostgresAuditLog`
# (SQLAlchemy backend) satisfy this shape. Declaring it as a ``Protocol``
# (not an ``ABC``) avoids forcing either concrete class to inherit from
# it — nominal subtyping isn't available across the persistence /
# shared boundary without an import cycle, and structural typing is
# exactly the right tool for "pick whichever backend the factory wired".
#
# The factory (``backend.shared.factory``) produces one of the two
# concrete implementations based on whether ``settings.database_url``
# is set, then hands it off to ``ToolExecutor`` / ``Orchestrator`` /
# ``BaseAgent`` subclasses — all of which now accept ``IAuditLog |
# None`` rather than naming the concrete ``ImmutableAuditLog`` type.
#
# ``@runtime_checkable`` lets tests use ``isinstance(x, IAuditLog)``
# if they ever need it — the primary use is still static type-checking.
@runtime_checkable
class IAuditLog(Protocol):
    """Structural port for the hash-chained audit log."""

    def log_action(
        self,
        agent_id: str,
        action: str,
        detail: str,
        result: str,
        chain_of_thought: str = ...,
        metadata: dict[str, Any] | None = ...,
    ) -> str:
        """Append an entry and return its hash."""

    def read_all(self) -> list[dict[str, Any]]:
        """Return every persisted entry (oldest first)."""

    def verify_integrity(self) -> bool:
        """Re-walk the hash chain; ``True`` iff no tampering detected."""

    def get_entry_count(self) -> int:
        """Return the number of persisted entries."""

