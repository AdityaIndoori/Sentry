"""
TDD tests for CostCircuitBreaker and RateLimiter.
"""

import time
import pytest
from backend.shared.circuit_breaker import CostCircuitBreaker, RateLimiter


class TestCostCircuitBreaker:
    def test_starts_untripped(self, circuit_breaker):
        assert circuit_breaker.is_tripped is False

    def test_trips_on_cost_exceeded(self):
        cb = CostCircuitBreaker(max_cost_usd=0.01, window_minutes=10)
        cb.record_usage(10000, 10000)  # Enough to exceed $0.01
        assert cb.is_tripped is True

    def test_reports_current_cost(self, circuit_breaker):
        circuit_breaker.record_usage(1000, 0)
        assert circuit_breaker.current_cost > 0

    def test_manual_reset(self):
        cb = CostCircuitBreaker(max_cost_usd=0.01)
        cb.record_usage(10000, 10000)
        assert cb.is_tripped is True
        cb.reset()
        assert cb.is_tripped is False
        assert cb.current_cost == 0

    def test_status_dict(self, circuit_breaker):
        status = circuit_breaker.get_status()
        assert "tripped" in status
        assert "current_cost_usd" in status
        assert "max_cost_usd" in status


class TestRateLimiter:
    def test_first_call_allowed(self, rate_limiter):
        assert rate_limiter.is_allowed("test", 10) is True

    def test_second_call_blocked(self, rate_limiter):
        rate_limiter.record("test")
        assert rate_limiter.is_allowed("test", 10) is False

    def test_different_keys_independent(self, rate_limiter):
        rate_limiter.record("key_a")
        assert rate_limiter.is_allowed("key_b", 10) is True

    def test_remaining_time(self, rate_limiter):
        rate_limiter.record("test")
        remaining = rate_limiter.get_remaining("test", 60)
        assert remaining > 0
        assert remaining <= 60

    def test_unrecorded_key_zero_remaining(self, rate_limiter):
        assert rate_limiter.get_remaining("never_used", 60) == 0
