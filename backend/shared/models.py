"""
Domain models for Sentry.
Pure data classes with no external dependencies (Clean Architecture inner layer).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class IncidentSeverity(Enum):
    """Severity classification for incidents."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentState(Enum):
    """State machine states for incident lifecycle."""
    IDLE = "idle"
    TRIAGE = "triage"
    DIAGNOSIS = "diagnosis"
    REMEDIATION = "remediation"
    VERIFICATION = "verification"
    RESOLVED = "resolved"
    ESCALATED = "escalated"


class ActivityType(Enum):
    """Types of activity log entries."""
    PHASE_START = "phase_start"
    PHASE_COMPLETE = "phase_complete"
    LLM_CALL = "llm_call"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    DECISION = "decision"
    ERROR = "error"
    INFO = "info"


class ToolCategory(Enum):
    """Tool permission categories."""
    READ_ONLY = "read_only"
    ACTIVE = "active"


@dataclass
class LogEvent:
    """Represents a detected log event that triggers analysis."""
    source_file: str
    line_content: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    matched_pattern: str = ""
    line_number: int = 0

    def to_dict(self) -> dict:
        return {
            "source_file": self.source_file,
            "line_content": self.line_content,
            "timestamp": self.timestamp.isoformat(),
            "matched_pattern": self.matched_pattern,
            "line_number": self.line_number,
        }


@dataclass
class ActivityEntry:
    """A single entry in an incident's activity log."""
    timestamp: datetime
    activity_type: ActivityType
    phase: str  # which phase this occurred in
    title: str  # short summary (e.g. "Called read_file")
    detail: str = ""  # longer detail (tool output, LLM reasoning, etc.)
    metadata: dict = field(default_factory=dict)  # extra info (tool args, tokens, etc.)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "activity_type": self.activity_type.value,
            "phase": self.phase,
            "title": self.title,
            "detail": self.detail[:1000] if self.detail else "",
            "metadata": self.metadata,
        }


@dataclass
class Incident:
    """Represents a tracked incident through its lifecycle."""
    id: str
    symptom: str
    state: IncidentState = IncidentState.TRIAGE
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    root_cause: Optional[str] = None
    fix_applied: Optional[str] = None
    commit_id: Optional[str] = None  # Git commit hash of the fix (if auto-committed)
    triage_result: Optional[str] = None
    log_events: list = field(default_factory=list)
    activity_log: list = field(default_factory=list)  # list[ActivityEntry]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    retry_count: int = 0
    cost_usd: float = 0.0
    vectors: list = field(default_factory=list)
    current_agent_action: Optional[str] = None  # live status text

    def log_activity(
        self,
        activity_type: ActivityType,
        phase: str,
        title: str,
        detail: str = "",
        metadata: dict = None,
    ) -> None:
        """Append an activity entry to the incident log."""
        entry = ActivityEntry(
            timestamp=datetime.now(timezone.utc),
            activity_type=activity_type,
            phase=phase,
            title=title,
            detail=detail,
            metadata=metadata or {},
        )
        self.activity_log.append(entry)

    def to_dict(self) -> dict:
        # Bug fix #13: log_events may contain LogEvent objects or dicts.
        # Ensure all entries are serializable dicts.
        serialized_log_events = []
        for evt in self.log_events:
            if isinstance(evt, dict):
                serialized_log_events.append(evt)
            elif hasattr(evt, 'to_dict'):
                serialized_log_events.append(evt.to_dict())
            else:
                serialized_log_events.append(str(evt))

        return {
            "id": self.id,
            "symptom": self.symptom,
            "state": self.state.value,
            "severity": self.severity.value,
            "root_cause": self.root_cause,
            "fix_applied": self.fix_applied,
            "commit_id": self.commit_id,
            "triage_result": self.triage_result,
            "log_events": serialized_log_events,
            "created_at": self.created_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "retry_count": self.retry_count,
            "cost_usd": self.cost_usd,
            "vectors": self.vectors,
            "current_agent_action": self.current_agent_action,
            "activity_log": [a.to_dict() for a in self.activity_log],
            "phase_summary": self._phase_summary(),
        }

    def _phase_summary(self) -> dict:
        """Summarize the status of each phase for the progress stepper.

        Bug fix #4: resolved/escalated are terminal states, not phases.
        When resolved, all 4 phases should be marked complete.
        When escalated, phases up to current should be complete, current is 'error'.
        """
        phases = ["triage", "diagnosis", "remediation", "verification"]
        state_order = {
            "idle": -1, "triage": 0, "diagnosis": 1,
            "remediation": 2, "verification": 3,
            "resolved": 4, "escalated": 4,
        }
        current_idx = state_order.get(self.state.value, -1)
        summary = {}
        for i, phase in enumerate(phases):
            if i < current_idx:
                summary[phase] = "complete"
            elif i == current_idx:
                summary[phase] = "active"
            else:
                summary[phase] = "pending"
        # Terminal states: mark outcome without adding extra phase keys
        if self.state == IncidentState.RESOLVED:
            # All phases are done
            for phase in phases:
                summary[phase] = "complete"
            summary["outcome"] = "resolved"
        elif self.state == IncidentState.ESCALATED:
            summary["outcome"] = "escalated"
        return summary


@dataclass
class ToolCall:
    """Represents a tool invocation request from the LLM."""
    tool_name: str
    arguments: dict = field(default_factory=dict)
    category: ToolCategory = ToolCategory.READ_ONLY


@dataclass
class ToolResult:
    """Result of a tool execution."""
    tool_name: str
    success: bool
    output: str = ""
    error: Optional[str] = None
    audit_only: bool = False  # True if tool was blocked due to AUDIT mode

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "output": self.output[:500] if self.output else "",
            "error": self.error,
            "audit_only": self.audit_only,
        }


@dataclass
class MemoryEntry:
    """A single incident record in long-term memory."""
    id: str
    symptom: str
    root_cause: str
    fix: str
    vectors: list = field(default_factory=list)
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "symptom": self.symptom,
            "root_cause": self.root_cause,
            "fix": self.fix,
            "vectors": self.vectors,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MemoryEntry":
        return cls(
            id=data.get("id", ""),
            symptom=data.get("symptom", ""),
            root_cause=data.get("root_cause", ""),
            fix=data.get("fix", ""),
            vectors=data.get("vectors", []),
            timestamp=data.get("timestamp", ""),
        )


@dataclass
class CostTracker:
    """Tracks API cost to enforce circuit breaker."""
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    window_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Claude pricing (approximate)
    INPUT_COST_PER_1K: float = 0.015
    OUTPUT_COST_PER_1K: float = 0.075

    @property
    def estimated_cost_usd(self) -> float:
        input_cost = (self.total_input_tokens / 1000) * self.INPUT_COST_PER_1K
        output_cost = (self.total_output_tokens / 1000) * self.OUTPUT_COST_PER_1K
        return round(input_cost + output_cost, 4)

    def add_usage(self, input_tokens: int, output_tokens: int) -> None:
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens

    def reset(self) -> None:
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.window_start = datetime.now(timezone.utc)
