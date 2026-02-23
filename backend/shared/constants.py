"""
Named constants — replaces magic numbers throughout the codebase.

All tunable limits and thresholds are defined here as named constants
with descriptive names. This makes the code self-documenting and
provides a single place to adjust operational parameters.
"""

# ── Log Watcher ──────────────────────────────────────────────

MAX_EVENT_QUEUE_SIZE = 100
"""Maximum number of log events that can be buffered in the watcher queue.
Events are dropped when the queue is full."""

# ── Tool Execution ───────────────────────────────────────────

MAX_TOOL_RESULT_IN_PROMPT = 2000
"""Maximum characters from a single tool result appended to the LLM prompt."""

MAX_PROMPT_SIZE = 50000
"""Maximum total prompt size (chars) before truncation in diagnosis/remediation loops."""

MAX_DIAGNOSTIC_OUTPUT = 5000
"""Maximum characters returned from run_diagnostics tool."""

MAX_FETCH_CONTENT = 10000
"""Maximum characters returned from fetch_docs tool."""

# ── Model Serialization ─────────────────────────────────────

MAX_TOOL_OUTPUT_PREVIEW = 500
"""Maximum characters of tool output included in ToolResult.to_dict()."""

MAX_ACTIVITY_DETAIL_LENGTH = 1000
"""Maximum characters of detail text in ActivityEntry.to_dict()."""

MAX_PARSED_FIELD_LENGTH = 500
"""Maximum characters for parsed fields in schema fallback parsing."""

# ── Resolved Incidents ───────────────────────────────────────

MAX_RESOLVED_INCIDENTS = 100
"""FIFO cap on the resolved incidents list to prevent unbounded memory growth."""

# ── Log Line Sanitization ────────────────────────────────────

MAX_LOG_LINE_LENGTH = 500
"""Maximum characters from a log line before truncation."""
