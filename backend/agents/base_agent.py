"""
Base Agent - Abstract base class for all agents.

Each agent:
1. Registers with the Vault to get a unique NHI
2. Requests JIT credentials before each operation
3. Has its I/O scanned by the AI Gateway
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

from backend.shared.vault import AgentRole, LocalVault, NonHumanIdentity, IVault
from backend.shared.ai_gateway import AIGateway

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class for all Sentry agents."""

    def __init__(self, vault: IVault, role: AgentRole, gateway: AIGateway):
        self._vault = vault
        self._gateway = gateway
        self._nhi = vault.register_agent(role)
        logger.info(f"Agent registered: {self._nhi.agent_id} (role={role.value})")

    @property
    def nhi(self) -> NonHumanIdentity:
        """This agent's unique Non-Human Identity."""
        return self._nhi

    @property
    def agent_id(self) -> str:
        return self._nhi.agent_id

    def _get_credential(self, scope: str, ttl: int = 60):
        """Request a JIT credential from the vault."""
        cred = self._vault.issue_credential(self.agent_id, scope=scope, ttl_seconds=ttl)
        if not cred:
            raise PermissionError(
                f"Agent {self.agent_id} denied credential for scope={scope}"
            )
        return cred

    def _scan_input(self, text: str) -> str:
        """Scan input through AI Gateway. Raises if unsafe."""
        result = self._gateway.scan_input(text)
        if not result.is_safe:
            logger.warning(
                f"BLOCKED INPUT for {self.agent_id}: threats={result.threats}"
            )
            raise ValueError(
                f"Input blocked by AI Gateway: {result.threats}"
            )
        return text

    def _scan_and_redact_output(self, text: str) -> str:
        """Scan and redact output through AI Gateway."""
        scan = self._gateway.scan_output(text)
        if not scan.is_safe:
            logger.warning(
                f"PII detected in output for {self.agent_id}: {scan.threats}"
            )
            return self._gateway.redact_output(text)
        return text
