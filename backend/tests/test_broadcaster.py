"""
Unit tests for :class:`backend.api.broadcaster.IncidentBroadcaster`.

These tests lock in the fan-out contract used by the /api/stream/incidents
SSE endpoint: multiple subscribers, back-pressure, shutdown semantics.
"""

from __future__ import annotations

import asyncio

import pytest

from backend.api.broadcaster import DEFAULT_QUEUE_SIZE, IncidentBroadcaster


@pytest.mark.asyncio
async def test_single_subscriber_receives_event():
    b = IncidentBroadcaster()
    async with b.subscribe() as q:
        assert b.publish_nowait({"kind": "hello"}) == 1
        got = await asyncio.wait_for(q.get(), timeout=1.0)
        assert got == {"kind": "hello"}


@pytest.mark.asyncio
async def test_multiple_subscribers_all_receive():
    b = IncidentBroadcaster()
    async with b.subscribe() as q1, b.subscribe() as q2, b.subscribe() as q3:
        delivered = b.publish_nowait({"kind": "fan-out"})
        assert delivered == 3
        for q in (q1, q2, q3):
            got = await asyncio.wait_for(q.get(), timeout=1.0)
            assert got == {"kind": "fan-out"}


@pytest.mark.asyncio
async def test_subscriber_removed_on_context_exit():
    b = IncidentBroadcaster()
    assert b.subscriber_count() == 0
    async with b.subscribe() as _q:
        assert b.subscriber_count() == 1
    assert b.subscriber_count() == 0


@pytest.mark.asyncio
async def test_publish_with_no_subscribers_does_not_raise():
    b = IncidentBroadcaster()
    # No-op; must not raise.
    assert b.publish_nowait({"kind": "lonely"}) == 0


@pytest.mark.asyncio
async def test_full_queue_drops_new_event_for_that_subscriber():
    b = IncidentBroadcaster(queue_size=2)
    async with b.subscribe() as q:
        # Fill the queue (capacity 2).
        assert b.publish_nowait({"n": 1}) == 1
        assert b.publish_nowait({"n": 2}) == 1
        # Third push should be dropped for this subscriber.
        assert b.publish_nowait({"n": 3}) == 0
        # Existing items are preserved (drop-new, not drop-old).
        assert (await q.get())["n"] == 1
        assert (await q.get())["n"] == 2
        # Queue is now drainable again.
        assert b.publish_nowait({"n": 4}) == 1
        assert (await q.get())["n"] == 4


@pytest.mark.asyncio
async def test_slow_subscriber_does_not_block_fast_subscriber():
    b = IncidentBroadcaster(queue_size=2)
    async with b.subscribe(), b.subscribe() as fast:
        # Fill slow's queue.
        b.publish_nowait({"n": 1})
        b.publish_nowait({"n": 2})
        # Drain fast so its queue has room.
        assert (await fast.get())["n"] == 1
        assert (await fast.get())["n"] == 2
        # Publish a 3rd event — slow drops it, fast receives it.
        delivered = b.publish_nowait({"n": 3})
        assert delivered == 1
        got = await asyncio.wait_for(fast.get(), timeout=1.0)
        assert got["n"] == 3


@pytest.mark.asyncio
async def test_close_wakes_all_subscribers_with_sentinel():
    b = IncidentBroadcaster()
    async with b.subscribe() as q1, b.subscribe() as q2:
        await b.close()
        # After close, both queues see the None sentinel.
        assert await asyncio.wait_for(q1.get(), timeout=1.0) is None
        assert await asyncio.wait_for(q2.get(), timeout=1.0) is None


@pytest.mark.asyncio
async def test_publish_after_close_is_a_noop():
    b = IncidentBroadcaster()
    await b.close()
    assert b.publish_nowait({"kind": "too-late"}) == 0


@pytest.mark.asyncio
async def test_subscribe_after_close_yields_silent_queue():
    """Subscribing after close still yields a queue (for API cleanliness)
    but the queue never receives any events."""
    b = IncidentBroadcaster()
    await b.close()
    async with b.subscribe() as q:
        # publish_nowait is a no-op post-close, so the queue stays empty.
        assert b.publish_nowait({"kind": "ghost"}) == 0
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(q.get(), timeout=0.05)


@pytest.mark.asyncio
async def test_default_queue_size_is_sensible():
    # Not strict on the exact number, but lock it against accidental
    # shrinkage to something that couldn't hold one full incident lifecycle.
    assert DEFAULT_QUEUE_SIZE >= 16
