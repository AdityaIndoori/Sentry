"""
Pydantic models for tool argument schemas — single source of truth.

Production hardening #3: Tool definitions and argument validation both derive
from these models. If a field changes here, both the LLM-facing schema and
the runtime validation update automatically.

Usage:
  - Tool.definition() calls `schema.model_json_schema()` for input_schema
  - MCPToolExecutor validates args with `schema.model_validate(args)` before execution
"""

from pydantic import BaseModel, Field


class ReadFileArgs(BaseModel):
    """Arguments for read_file tool."""
    path: str = Field(description="Relative path from project root")


class GrepSearchArgs(BaseModel):
    """Arguments for grep_search tool."""
    query: str = Field(description="Regex pattern")
    path: str = Field(default=".", description="Relative directory to search")


class FetchDocsArgs(BaseModel):
    """Arguments for fetch_docs tool."""
    url: str = Field(description="URL to fetch")


class RunDiagnosticsArgs(BaseModel):
    """Arguments for run_diagnostics tool."""
    command: str = Field(description="Diagnostic command to run")


class ApplyPatchArgs(BaseModel):
    """Arguments for apply_patch tool."""
    file_path: str = Field(description="Relative path to file")
    diff: str = Field(description="Unified diff to apply (must include --- a/ and +++ b/ headers and @@ hunk headers)")


class RestartServiceArgs(BaseModel):
    """Arguments for restart_service tool.
    
    No parameters needed — the restart command is configured
    via the SERVICE_RESTART_CMD environment variable.
    """
    pass


def pydantic_to_input_schema(model: type[BaseModel]) -> dict:
    """
    Convert a Pydantic model to Anthropic-style input_schema.

    Strips Pydantic-specific keys (like 'title') that aren't needed
    by the LLM tool definition format.
    """
    schema = model.model_json_schema()
    # Remove top-level 'title' — LLM doesn't need it
    schema.pop("title", None)
    # Ensure 'type' is 'object'
    schema.setdefault("type", "object")
    return schema


# Map tool names to their arg models for runtime validation
TOOL_ARG_MODELS: dict[str, type[BaseModel]] = {
    "read_file": ReadFileArgs,
    "grep_search": GrepSearchArgs,
    "fetch_docs": FetchDocsArgs,
    "run_diagnostics": RunDiagnosticsArgs,
    "apply_patch": ApplyPatchArgs,
    "restart_service": RestartServiceArgs,
}
