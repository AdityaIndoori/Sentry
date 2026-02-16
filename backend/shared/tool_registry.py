"""
Trusted Tool Registry - Allowlist of pre-vetted tools per agent role.

Agents are restricted to a strictly defined set of tools.
No agent can construct arbitrary calls; they must select from
the registered catalog for their role.

Zero Trust principle: Least privilege - each agent only gets
the tools it needs, nothing more.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from backend.shared.vault import AgentRole

logger = logging.getLogger(__name__)


@dataclass
class ToolDefinition:
    """A registered tool with its access control list."""
    name: str
    description: str = ""
    allowed_roles: List[AgentRole] = field(default_factory=list)
    is_active: bool = False  # True = write/mutate, False = read-only


class TrustedToolRegistry:
    """
    Central registry of all allowed tools.

    Agents MUST check this registry before executing any tool.
    Unregistered tools are always blocked.
    """

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}

    def register(
        self,
        name: str,
        allowed_roles: List[AgentRole],
        description: str = "",
        is_active: bool = False,
    ) -> None:
        """Register a tool with its allowed roles."""
        self._tools[name] = ToolDefinition(
            name=name,
            description=description,
            allowed_roles=allowed_roles,
            is_active=is_active,
        )
        logger.info(
            f"Registered tool: {name} "
            f"(roles={[r.value for r in allowed_roles]}, active={is_active})"
        )

    def is_allowed(self, tool_name: str, role: AgentRole) -> bool:
        """Check if a tool is allowed for a given agent role."""
        tool = self._tools.get(tool_name)
        if not tool:
            logger.warning(f"BLOCKED: Unregistered tool '{tool_name}'")
            return False
        if role not in tool.allowed_roles:
            logger.warning(
                f"BLOCKED: Tool '{tool_name}' not allowed for role '{role.value}'"
            )
            return False
        return True

    def get_tools_for_role(self, role: AgentRole) -> list[str]:
        """Get all tool names allowed for a specific role."""
        return [
            name for name, tool in self._tools.items()
            if role in tool.allowed_roles
        ]

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """Get a tool definition by name."""
        return self._tools.get(name)

    def get_all_tools(self) -> list[ToolDefinition]:
        """Get all registered tools."""
        return list(self._tools.values())


def create_default_registry() -> TrustedToolRegistry:
    """
    Factory: create the standard Claude Sentry tool registry
    with role-based access as defined in the design doc.

    Role mapping (least privilege):
      - SUPERVISOR: all tools (override)
      - TRIAGE: read_file, grep_search, fetch_docs (read-only)
      - DETECTIVE: read_file, grep_search, fetch_docs, run_diagnostics
      - SURGEON: apply_patch, restart_service (active tools)
      - VALIDATOR: read_file, grep_search, run_diagnostics (verify fixes)
    """
    registry = TrustedToolRegistry()

    # Read-only tools
    registry.register(
        name="read_file",
        description="Read a file within PROJECT_ROOT",
        allowed_roles=[
            AgentRole.SUPERVISOR,
            AgentRole.TRIAGE,
            AgentRole.DETECTIVE,
            AgentRole.VALIDATOR,
        ],
        is_active=False,
    )
    registry.register(
        name="grep_search",
        description="Search files with pattern matching (max 100 results)",
        allowed_roles=[
            AgentRole.SUPERVISOR,
            AgentRole.TRIAGE,
            AgentRole.DETECTIVE,
            AgentRole.VALIDATOR,
        ],
        is_active=False,
    )
    registry.register(
        name="fetch_docs",
        description="Fetch documentation from allow-listed domains",
        allowed_roles=[
            AgentRole.SUPERVISOR,
            AgentRole.TRIAGE,
            AgentRole.DETECTIVE,
        ],
        is_active=False,
    )

    # Active tools (require ACTIVE mode or SRE permission)
    registry.register(
        name="run_diagnostics",
        description="Run whitelisted diagnostic commands (ps, netstat, curl, tail)",
        allowed_roles=[
            AgentRole.SUPERVISOR,
            AgentRole.DETECTIVE,
            AgentRole.VALIDATOR,
        ],
        is_active=True,
    )
    registry.register(
        name="apply_patch",
        description="Apply a diff patch to a file (auto-creates .bak backup)",
        allowed_roles=[
            AgentRole.SUPERVISOR,
            AgentRole.SURGEON,
        ],
        is_active=True,
    )
    registry.register(
        name="restart_service",
        description="Restart a system service (rate limited: 1 per 10min)",
        allowed_roles=[
            AgentRole.SUPERVISOR,
            AgentRole.SURGEON,
        ],
        is_active=True,
    )

    return registry
