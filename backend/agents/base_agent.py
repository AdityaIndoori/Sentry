"""
Base Agent - Abstract base class for all agents.

Each agent:
1. Registers with the Vault to get a unique NHI
2. Requests JIT credentials before each operation
3. Has its I/O scanned by the AI Gateway
4. Logs all security-critical actions to the immutable audit trail
5. Sanitizes all inputs before processing
6. All LLM calls and tool executions are automatically activity-logged
   via _call_llm() and _call_tool() — the only way to access these resources
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

from backend.shared.vault import AgentRole, LocalVault, NonHumanIdentity, IVault
from backend.shared.ai_gateway import AIGateway
from backend.shared.audit_log import ImmutableAuditLog
from backend.shared.models import ToolCall, ToolResult
from backend.shared.security import SecurityGuard

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class for all Sentry agents.
    
    LLM and tool executor are stored with name-mangling (__llm, __tools)
    so subclasses cannot access them directly. The only way to call the LLM
    or execute a tool is through _call_llm() and _call_tool(), which
    automatically log activity entries. This guarantees every LLM call and
    tool execution is activity-logged — no agent can bypass this.
    """

    def __init__(
        self,
        vault: IVault,
        role: AgentRole,
        gateway: AIGateway,
        audit_log: Optional[ImmutableAuditLog] = None,
        security: Optional[SecurityGuard] = None,
        llm: Any = None,
        tools: Any = None,
    ):
        self._vault = vault
        self._gateway = gateway
        self._audit_log = audit_log
        self._security = security
        self._role = role
        # Name-mangled: subclasses cannot access self.__llm or self.__tools
        # They MUST use self._call_llm() and self._call_tool() which auto-log
        self.__llm = llm
        self.__tools = tools
        # Activity log — collected during run(), returned to graph node
        self._activities: list[dict] = []
        self._call_count: int = 0
        # Register NHI
        self._nhi = vault.register_agent(role)
        logger.info(f"Agent registered: {self._nhi.agent_id} (role={role.value})")

    @property
    def nhi(self) -> NonHumanIdentity:
        """This agent's unique Non-Human Identity."""
        return self._nhi

    @property
    def agent_id(self) -> str:
        return self._nhi.agent_id

    # ── Activity logging (returned to graph node) ─────────

    def _log_activity(self, activity_type: str, message: str, detail: str = "",
                      metadata: Optional[dict] = None):
        """Record an activity entry. Graph node applies these to the incident after run()."""
        self._activities.append({
            "activity_type": activity_type,
            "agent": self._role.value,
            "message": message,
            "detail": detail or "",
            "metadata": metadata or {},
        })

    # ── LLM access (the ONLY way to call the LLM) ────────

    async def _call_llm(self, prompt: str, effort: str, tools: list = None) -> dict:
        """Call the LLM. Automatically logs LLM_CALL and INFO activities.
        
        This is the ONLY way to access the LLM from any agent.
        Direct access to self.__llm is blocked by name mangling.
        """
        self._call_count += 1
        self._log_activity(
            "LLM_CALL",
            f"Calling LLM (effort: {effort}, call #{self._call_count})",
            metadata={"effort": effort, "call_number": self._call_count},
        )

        response = await self.__llm.analyze(prompt=prompt, effort=effort, tools=tools)

        input_tokens = response.get("input_tokens", 0)
        output_tokens = response.get("output_tokens", 0)
        self._log_activity(
            "INFO",
            "LLM response received",
            detail=f"tokens: {input_tokens} in / {output_tokens} out",
            metadata={"input_tokens": input_tokens, "output_tokens": output_tokens},
        )
        return response

    # ── Tool access (the ONLY way to execute a tool) ──────

    async def _call_tool(self, tool_name: str, arguments: dict) -> ToolResult:
        """Execute a tool. Automatically logs TOOL_CALL and TOOL_RESULT activities.
        
        This is the ONLY way to execute a tool from any agent.
        Direct access to self.__tools is blocked by name mangling.
        """
        args_summary = ", ".join(f"{k}={str(v)[:50]}" for k, v in arguments.items())
        self._log_activity(
            "TOOL_CALL",
            f"Calling {tool_name}",
            detail=args_summary,
            metadata={"tool": tool_name, "args": {k: str(v)[:100] for k, v in arguments.items()}},
        )

        call = ToolCall(tool_name=tool_name, arguments=arguments)
        result = await self.__tools.execute(call, caller_role=self._role)

        result_text = result.output or result.error or ""
        self._log_activity(
            "TOOL_RESULT",
            f"{tool_name} → {'✓' if result.success else '✗'}",
            detail=result_text[:300],
            metadata={"success": result.success, "audit_only": getattr(result, 'audit_only', False)},
        )
        return result

    def _get_tool_definitions(self, category: str = "all") -> list:
        """Get tool definitions for LLM tool_use parameter. No logging needed."""
        if self.__tools is None:
            return []
        if category == "read_only" and hasattr(self.__tools, 'get_read_only_tool_definitions'):
            return self.__tools.get_read_only_tool_definitions()
        if category == "remediation" and hasattr(self.__tools, 'get_remediation_tool_definitions'):
            return self.__tools.get_remediation_tool_definitions()
        if hasattr(self.__tools, 'get_tool_definitions'):
            return self.__tools.get_tool_definitions()
        return []

    # ── Audit trail (security events) ─────────────────────

    def _audit(self, action: str, detail: str, result: str = "", metadata: Optional[dict] = None):
        """Log an action to the immutable audit trail (if configured)."""
        if self._audit_log:
            self._audit_log.log_action(
                agent_id=self.agent_id,
                action=action,
                detail=detail,
                result=result,
                metadata=metadata,
            )

    # ── Credential management ─────────────────────────────

    def _get_credential(self, scope: str, ttl: int = 60):
        """Request a JIT credential from the vault."""
        cred = self._vault.issue_credential(self.agent_id, scope=scope, ttl_seconds=ttl)
        if not cred:
            self._audit("credential_denied", f"scope={scope}", "denied")
            raise PermissionError(
                f"Agent {self.agent_id} denied credential for scope={scope}"
            )
        self._audit(
            "credential_issued",
            f"scope={scope}, ttl={ttl}s",
            f"credential_id={cred.credential_id}",
        )
        return cred

    # ── Input/Output scanning ─────────────────────────────

    def _scan_input(self, text: str) -> str:
        """Sanitize input, then scan through AI Gateway. Raises if unsafe."""
        if self._security:
            sanitized = self._security.sanitize_input(text)
        else:
            dangerous = [";", "&&", "||", "|", "`", "$(", ">>", "<<"]
            sanitized = text
            for char in dangerous:
                sanitized = sanitized.replace(char, "")
            sanitized = sanitized.strip()

        result = self._gateway.scan_input(sanitized)
        if not result.is_safe:
            logger.warning(
                f"BLOCKED INPUT for {self.agent_id}: threats={result.threats}"
            )
            self._audit(
                "input_blocked",
                f"threats={result.threats}",
                "blocked",
                metadata={"threats": result.threats},
            )
            raise ValueError(
                f"Input blocked by AI Gateway: {result.threats}"
            )
        return sanitized

    def _scan_and_redact_output(self, text: str) -> str:
        """Scan and redact output through AI Gateway."""
        scan = self._gateway.scan_output(text)
        if not scan.is_safe:
            logger.warning(
                f"PII detected in output for {self.agent_id}: {scan.threats}"
            )
            self._audit(
                "pii_detected",
                f"threats={scan.threats}",
                "redacted",
                metadata={"threats": scan.threats},
            )
            return self._gateway.redact_output(text)
        return text
