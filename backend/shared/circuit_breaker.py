"""
Circuit breaker for cost control and rate limiting.
Prevents runaway API costs and enforces tool cooldowns.

Concurrency: both classes use threading locks because they are read/written
from both synchronous audit paths (ToolExecutor) and asynchronous orchestrator
paths; threading.Lock is correct and cheap for the low-contention paths here.
"""

import logging
import threading
import time
from datetime import UTC, datetime, timedelta

from .models import CostTracker

logger = logging.getLogger(__name__)


class CostCircuitBreaker:
    """Breaks the loop if API costs exceed threshold.

    Safe under concurrent token-usage recording from multiple incidents.
    """

    def __init__(self, max_cost_usd: float = 5.0, window_minutes: int = 10):
        self._max_cost = max_cost_usd
        self._window_minutes = window_minutes
        self._tracker = CostTracker()
        self._tripped = False
        self._lock = threading.Lock()

    @property
    def is_tripped(self) -> bool:
        with self._lock:
            self._check_window_reset_locked()
            return self._tripped

    @property
    def current_cost(self) -> float:
        with self._lock:
            return self._tracker.estimated_cost_usd

    def record_usage(self, input_tokens: int, output_tokens: int) -> None:
        """Record token usage and check if breaker should trip."""
        incremental_cost = 0.0
        with self._lock:
            self._check_window_reset_locked()
            prev_cost = self._tracker.estimated_cost_usd
            self._tracker.add_usage(input_tokens, output_tokens)
            cost = self._tracker.estimated_cost_usd
            incremental_cost = max(0.0, cost - prev_cost)
            if cost >= self._max_cost:
                self._tripped = True
                logger.critical(
                    f"CIRCUIT BREAKER TRIPPED: ${cost:.2f} >= ${self._max_cost:.2f} "
                    f"in {self._window_minutes} min window"
                )

        # P2.3b-full: report the *increment* to the USD cost counter so
        # Prometheus totals match the tracker's running cost. Done OUTSIDE
        # the lock to avoid holding it during an external call.
        if incremental_cost > 0:
            try:
                from backend.shared.metrics import observe_llm_cost
                observe_llm_cost(incremental_cost)
            except Exception:  # pragma: no cover
                pass

    def reset(self) -> None:
        """Manual reset of the circuit breaker."""
        with self._lock:
            self._tracker.reset()
            self._tripped = False
            logger.info("Circuit breaker manually reset")

    def _check_window_reset_locked(self) -> None:
        """Auto-reset if the time window has elapsed. MUST hold self._lock."""
        elapsed = datetime.now(UTC) - self._tracker.window_start
        if elapsed > timedelta(minutes=self._window_minutes):
            self._tracker.reset()
            self._tripped = False

    def get_status(self) -> dict[str, float | int | bool]:
        with self._lock:
            self._check_window_reset_locked()
            return {
                "tripped": self._tripped,
                "current_cost_usd": self._tracker.estimated_cost_usd,
                "max_cost_usd": self._max_cost,
                "window_minutes": self._window_minutes,
                "input_tokens": self._tracker.total_input_tokens,
                "output_tokens": self._tracker.total_output_tokens,
            }


class RateLimiter:
    """Simple rate limiter for tool execution cooldowns.

    Thread-safe — check-and-record is atomic so two concurrent is_allowed()
    calls cannot both return True inside the cooldown window.
    """

    def __init__(self) -> None:
        self._last_call: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str, cooldown_seconds: int) -> bool:
        """Check if an action is allowed given its cooldown.

        Atomic: when this returns True it has also recorded the action,
        so a concurrent caller will correctly see the cooldown.
        """
        with self._lock:
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
        with self._lock:
            self._last_call[key] = time.time()

    def get_remaining(self, key: str, cooldown_seconds: int) -> float:
        """Get seconds remaining until action is allowed."""
        with self._lock:
            now = time.time()
            last = self._last_call.get(key, 0)
            remaining = cooldown_seconds - (now - last)
            return max(0, remaining)
