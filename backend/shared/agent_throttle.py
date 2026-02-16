"""
Agent Throttle - Strict rate limiting for agent actions.

Prevents runaway loops by enforcing "Max N actions per minute"
per agent. Each agent has its own independent counter.

Zero Trust principle: Limit blast radius of compromised agents.
"""

import logging
import time
from collections import defaultdict
from threading import Lock

logger = logging.getLogger(__name__)


class AgentThrottle:
    """
    Per-agent rate limiter using sliding window counters.

    Each agent gets max_actions_per_minute actions. Once exhausted,
    further actions are blocked until the window slides.
    """

    def __init__(self, max_actions_per_minute: int = 5):
        self._max_actions = max_actions_per_minute
        self._window_seconds = 60.0
        self._actions: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, agent_id: str, action_type: str = "generic") -> bool:
        """
        Check if an agent is allowed to perform an action.
        Records the action if allowed.
        """
        with self._lock:
            now = time.time()
            cutoff = now - self._window_seconds

            # Prune old actions outside the window
            self._actions[agent_id] = [
                t for t in self._actions[agent_id] if t > cutoff
            ]

            if len(self._actions[agent_id]) >= self._max_actions:
                logger.warning(
                    f"THROTTLED: Agent {agent_id} exceeded {self._max_actions} "
                    f"actions/min (action={action_type})"
                )
                return False

            # Record this action
            self._actions[agent_id].append(now)
            return True

    def get_remaining(self, agent_id: str) -> int:
        """Get number of remaining allowed actions for an agent."""
        with self._lock:
            now = time.time()
            cutoff = now - self._window_seconds
            self._actions[agent_id] = [
                t for t in self._actions[agent_id] if t > cutoff
            ]
            return max(0, self._max_actions - len(self._actions[agent_id]))

    def reset(self, agent_id: str) -> None:
        """Reset the throttle for a specific agent."""
        with self._lock:
            self._actions[agent_id] = []

    def reset_all(self) -> None:
        """Reset all throttles."""
        with self._lock:
            self._actions.clear()
