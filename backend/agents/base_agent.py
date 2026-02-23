"""
Base Agent - Abstract base class for all agents.

Each agent:
1. Registers with the Vault to get a unique NHI
2. Requests JIT credentials before each operation
3. Has its I/O scanned by the AI Gateway
4. Logs all security-critical actions to the immutable audit trail
5. Sanitizes all inputs before processing
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

from backend.shared.vault import AgentRole, LocalVault, NonHumanIdentity, IVault
from backend.shared.ai_gateway import AIGateway
from backend.shared.audit_log import ImmutableAuditLog
from backend.shared.security import SecurityGuard

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class for all Sentry agents."""

    def __init__(
        self,
        vault: IVault,
        role: AgentRole,
        gateway: AIGateway,
        audit_log: Optional[ImmutableAuditLog] = None,
        security: Optional[SecurityGuard] = None,
    ):
        self._vault = vault
        self._gateway = gateway
        self._audit_log = audit_log
        self._security = security
        self._nhi = vault.register_agent(role)
        logger.info(f"Agent registered: {self._nhi.agent_id} (role={role.value})")

    @property
    def nhi(self) -> NonHumanIdentity:
        """This agent's unique Non-Human Identity."""
        return self._nhi

    @property
    def agent_id(self) -> str:
        return self._nhi.agent_id

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

    def _scan_input(self, text: str) -> str:
        """Sanitize input, then scan through AI Gateway. Raises if unsafe."""
        # Step 1: Sanitize — strip dangerous shell characters
        # Uses SecurityGuard.sanitize_input() as single source of truth.
        # Falls back to inline sanitization if no SecurityGuard was injected.
        if self._security:
            sanitized = self._security.sanitize_input(text)
        else:
            # Fallback for agents created without a SecurityGuard (e.g. in tests)
            dangerous = [";", "&&", "||", "|", "`", "$(", ">>", "<<"]
            sanitized = text
            for char in dangerous:
                sanitized = sanitized.replace(char, "")
            sanitized = sanitized.strip()

        # Step 2: AI Gateway scan — detect prompt injection
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
