"""
Zero Trust Vault - Centralized secret management with JIT credentials.

Each agent gets a unique Non-Human Identity (NHI) and requests
short-lived credentials from this vault at the moment of need.
Credentials are revoked immediately after task completion.

This is a local implementation. In production, swap for
HashiCorp Vault or AWS Secrets Manager via the IVault interface.
"""

import hashlib
import hmac
import logging
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Optional

logger = logging.getLogger(__name__)


class AgentRole(Enum):
    """Roles for Non-Human Identities."""
    SUPERVISOR = "supervisor"
    TRIAGE = "triage"
    DETECTIVE = "detective"
    SURGEON = "surgeon"
    VALIDATOR = "validator"


@dataclass(frozen=True)
class NonHumanIdentity:
    """Unique identity for each agent - no shared service accounts."""
    agent_id: str          # e.g. "triage-a1b2c3"
    role: AgentRole
    fingerprint: str       # SHA-256 of creation params
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class JITCredential:
    """Short-lived credential issued to an agent for a specific operation."""
    credential_id: str
    agent_id: str
    token: str             # The actual secret token
    scope: str             # What this credential authorizes (e.g., "read_file", "llm_call")
    issued_at: float       # time.time()
    ttl_seconds: int       # How long this credential lives
    revoked: bool = False

    @property
    def is_expired(self) -> bool:
        return time.time() > (self.issued_at + self.ttl_seconds)

    @property
    def is_valid(self) -> bool:
        return not self.revoked and not self.is_expired


class IVault(ABC):
    """Interface for secret vault - swap for HashiCorp Vault in production."""

    @abstractmethod
    def register_agent(self, role: AgentRole) -> NonHumanIdentity:
        """Register a new agent and get its unique NHI."""

    @abstractmethod
    def issue_credential(
        self, agent_id: str, scope: str, ttl_seconds: int = 60
    ) -> Optional[JITCredential]:
        """Issue a Just-In-Time credential for a specific scope."""

    @abstractmethod
    def verify_credential(self, credential_id: str, agent_id: str, scope: str) -> bool:
        """Verify a credential is valid for the given agent and scope."""

    @abstractmethod
    def revoke_credential(self, credential_id: str) -> bool:
        """Immediately revoke a credential."""

    @abstractmethod
    def revoke_all(self) -> int:
        """KILL SWITCH: Revoke ALL credentials immediately. Returns count revoked."""

    @abstractmethod
    def get_agent(self, agent_id: str) -> Optional[NonHumanIdentity]:
        """Look up an agent by ID."""


class LocalVault(IVault):
    """
    In-process vault implementation for Zero Trust credential management.

    Thread-safe. In production, replace with HashiCorp Vault client.
    """

    def __init__(self, master_secret: str = ""):
        self._master_secret = master_secret or secrets.token_hex(32)
        self._agents: dict[str, NonHumanIdentity] = {}
        self._credentials: dict[str, JITCredential] = {}
        self._lock = Lock()
        self._killed = False  # Master kill switch state

    def register_agent(self, role: AgentRole) -> NonHumanIdentity:
        """Register a new agent with a unique NHI."""
        if self._killed:
            raise PermissionError("Vault is in kill switch state. All operations halted.")

        agent_suffix = secrets.token_hex(6)
        agent_id = f"{role.value}-{agent_suffix}"

        # Create a deterministic fingerprint
        fingerprint_input = f"{agent_id}:{role.value}:{self._master_secret}"
        fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()[:16]

        nhi = NonHumanIdentity(
            agent_id=agent_id,
            role=role,
            fingerprint=fingerprint,
        )

        with self._lock:
            self._agents[agent_id] = nhi

        logger.info(f"Registered agent: {agent_id} (role={role.value})")
        return nhi

    def issue_credential(
        self, agent_id: str, scope: str, ttl_seconds: int = 60
    ) -> Optional[JITCredential]:
        """Issue a short-lived JIT credential."""
        if self._killed:
            logger.warning(f"Vault killed - refusing credential for {agent_id}")
            return None

        with self._lock:
            if agent_id not in self._agents:
                logger.warning(f"Unknown agent requesting credential: {agent_id}")
                return None

            # Generate a unique token using HMAC
            token_input = f"{agent_id}:{scope}:{time.time()}:{secrets.token_hex(8)}"
            token = hmac.new(
                self._master_secret.encode(),
                token_input.encode(),
                hashlib.sha256,
            ).hexdigest()

            cred_id = f"cred-{secrets.token_hex(8)}"
            cred = JITCredential(
                credential_id=cred_id,
                agent_id=agent_id,
                token=token,
                scope=scope,
                issued_at=time.time(),
                ttl_seconds=ttl_seconds,
            )
            self._credentials[cred_id] = cred

        logger.debug(f"Issued credential {cred_id} to {agent_id} for scope={scope} (TTL={ttl_seconds}s)")
        return cred

    def verify_credential(self, credential_id: str, agent_id: str, scope: str) -> bool:
        """Verify a credential is valid, belongs to the agent, and matches scope."""
        with self._lock:
            cred = self._credentials.get(credential_id)
            if not cred:
                logger.warning(f"Credential not found: {credential_id}")
                return False
            if not cred.is_valid:
                logger.warning(f"Credential expired/revoked: {credential_id}")
                return False
            if cred.agent_id != agent_id:
                logger.warning(
                    f"Agent mismatch: cred belongs to {cred.agent_id}, "
                    f"requested by {agent_id}"
                )
                return False
            if cred.scope != scope:
                logger.warning(
                    f"Scope mismatch: cred scope={cred.scope}, "
                    f"requested scope={scope}"
                )
                return False
            return True

    def revoke_credential(self, credential_id: str) -> bool:
        """Immediately revoke a specific credential."""
        with self._lock:
            cred = self._credentials.get(credential_id)
            if cred:
                cred.revoked = True
                logger.info(f"Revoked credential: {credential_id}")
                return True
            return False

    def revoke_all(self) -> int:
        """KILL SWITCH: Revoke ALL credentials immediately."""
        with self._lock:
            self._killed = True
            count = 0
            for cred in self._credentials.values():
                if not cred.revoked:
                    cred.revoked = True
                    count += 1
            logger.critical(f"KILL SWITCH: Revoked {count} credentials")
            return count

    def get_agent(self, agent_id: str) -> Optional[NonHumanIdentity]:
        """Look up an agent by ID."""
        return self._agents.get(agent_id)

    @property
    def is_killed(self) -> bool:
        return self._killed

    def reset_kill_switch(self) -> None:
        """Reset the kill switch (requires manual intervention)."""
        with self._lock:
            self._killed = False
            logger.info("Kill switch reset")

    def get_active_credentials_count(self) -> int:
        """Return count of active (non-revoked, non-expired) credentials."""
        with self._lock:
            return sum(1 for c in self._credentials.values() if c.is_valid)

    def cleanup_expired(self) -> int:
        """Remove expired/revoked credentials from storage."""
        with self._lock:
            expired = [
                cid for cid, c in self._credentials.items()
                if not c.is_valid
            ]
            for cid in expired:
                del self._credentials[cid]
            return len(expired)
