"""
Circuit breaker for cost control and rate limiting.
Prevents runaway API costs and enforces tool cooldowns.
"""

import logging
import time
from datetime import datetime, timedelta, timezone

from .models import CostTracker

logger = logging.getLogger(__name__)


class CostCircuitBreaker:
    """Breaks the loop if API costs exceed threshold."""

    def __init__(self, max_cost_usd: float = 5.0, window_minutes: int = 10):
        self._max_cost = max_cost_usd
        self._window_minutes = window_minutes
        self._tracker = CostTracker()
        self._tripped = False

    @property
    def is_tripped(self) -> bool:
        self._check_window_reset()
        return self._tripped

    @property
    def current_cost(self) -> float:
        return self._tracker.estimated_cost_usd

    def record_usage(self, input_tokens: int, output_tokens: int) -> None:
        """Record token usage and check if breaker should trip."""
        self._check_window_reset()
        self._tracker.add_usage(input_tokens, output_tokens)
        cost = self._tracker.estimated_cost_usd
        if cost >= self._max_cost:
            self._tripped = True
            logger.critical(
                f"CIRCUIT BREAKER TRIPPED: ${cost:.2f} >= ${self._max_cost:.2f} "
                f"in {self._window_minutes} min window"
            )

    def reset(self) -> None:
        """Manual reset of the circuit breaker."""
        self._tracker.reset()
        self._tripped = False
        logger.info("Circuit breaker manually reset")

    def _check_window_reset(self) -> None:
        """Auto-reset if the time window has elapsed."""
        elapsed = datetime.now(timezone.utc) - self._tracker.window_start
        if elapsed > timedelta(minutes=self._window_minutes):
            self._tracker.reset()
            self._tripped = False

    def get_status(self) -> dict:
        return {
            "tripped": self.is_tripped,
            "current_cost_usd": self.current_cost,
            "max_cost_usd": self._max_cost,
            "window_minutes": self._window_minutes,
            "input_tokens": self._tracker.total_input_tokens,
            "output_tokens": self._tracker.total_output_tokens,
        }


class RateLimiter:
    """Simple rate limiter for tool execution cooldowns."""

    def __init__(self):
        self._last_call: dict[str, float] = {}

    def is_allowed(self, key: str, cooldown_seconds: int) -> bool:
        """Check if an action is allowed given its cooldown."""
        now = time.time()
        last = self._last_call.get(key, 0)
        if now - last < cooldown_seconds:
            remaining = cooldown_seconds - (now - last)
            logger.warning(
                f"Rate limited: {key} - {remaining:.0f}s remaining"
            )
            return False
        # Bug fix #9: Automatically record the action when check passes.
        # Previously, callers had to manually call record() after is_allowed(),
        # but failed attempts (e.g., failed restarts) never called record(),
        # allowing unlimited rapid retries of failing operations.
        self._last_call[key] = now
        return True

    def record(self, key: str) -> None:
        """Record that an action was taken (also called by is_allowed on success)."""
        self._last_call[key] = time.time()

    def get_remaining(self, key: str, cooldown_seconds: int) -> float:
        """Get seconds remaining until action is allowed."""
        now = time.time()
        last = self._last_call.get(key, 0)
        remaining = cooldown_seconds - (now - last)
        return max(0, remaining)
