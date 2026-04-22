"""
P2.4 — Incident broadcaster (in-process SSE fan-out).

Lightweight publish/subscribe channel used by the ``/api/stream/incidents``
endpoint to push live incident state updates to the dashboard without the
client having to poll ``/api/incidents`` every few seconds.

Design notes
------------
* **No broker required.** We stay in-process because Sentry runs as a
  single replica; a multi-replica deployment would need Redis / NATS,
  which is explicitly out of scope for the OSS-only hardening track.
* **Each subscriber owns an ``asyncio.Queue``.** The broadcaster pushes
  a JSON-serializable dict onto every live queue; slow consumers are
  dropped (queue full → oldest message discarded) rather than stalling
  the orchestrator's hot path.
* **Backpressure-safe.** ``publish_nowait`` never awaits and never
  raises; if a subscriber's queue is saturated the broadcaster logs
  once and drops the event for that subscriber.
* **Tests don't need sse-starlette.** The E2E tests subscribe directly
  to the broadcaster's ``subscribe()`` context manager and assert on
  the delivered dicts. The SSE wire format (``event: ...\\ndata: ...``)
  is produced only inside the FastAPI handler.

Public API
----------
* :class:`IncidentBroadcaster` — the fan-out primitive.
* :meth:`IncidentBroadcaster.publish_nowait(event: dict)` — non-blocking
  push called from the orchestrator.
* :meth:`IncidentBroadcaster.subscribe()` — async context manager
  yielding an ``asyncio.Queue[dict]`` for the lifetime of the
  subscriber (e.g. one HTTP request).
* :meth:`IncidentBroadcaster.close()` — cancel all subscribers (called
  from ``ServiceContainer.shutdown()``).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import AsyncIterator, Dict, Optional

logger = logging.getLogger(__name__)

# Per-subscriber queue capacity. Small enough that a slow dashboard
# can't pin RAM; big enough that a burst of state transitions during
# one incident (TRIAGE → DIAGNOSIS → REMEDIATION → VERIFICATION →
# RESOLVED) fits without dropping.
DEFAULT_QUEUE_SIZE = 64


class IncidentBroadcaster:
    """In-process fan-out for incident state updates.

    Thread-safety: every method is safe to call from any task on the
    same event loop. We do NOT support calling from a different loop /
    thread; there's no need in the current deployment model.
    """

    def __init__(self, *, queue_size: int = DEFAULT_QUEUE_SIZE) -> None:
        self._queue_size = queue_size
        self._subscribers: Dict[int, asyncio.Queue] = {}
        self._next_id = 0
        self._lock = asyncio.Lock()
        self._closed = False

    # ------------------------------------------------------------------
    # Publish side — called by the orchestrator.
    # ------------------------------------------------------------------

    def publish_nowait(self, event: dict) -> int:
        """Push ``event`` to every live subscriber without awaiting.

        Returns the number of subscribers that actually received the
        event (i.e. whose queue was not full). Full queues drop the
        *new* event (not the oldest one — FastAPI's SSE writer will
        typically catch up within one tick).

        Safe to call from any task on the event loop; never raises.
        """
        if self._closed:
            return 0

        delivered = 0
        dropped: list[int] = []
        # We iterate over a snapshot to avoid concurrent-mutation issues
        # if a subscriber unsubscribes mid-broadcast.
        for sub_id, q in list(self._subscribers.items()):
            try:
                q.put_nowait(event)
                delivered += 1
            except asyncio.QueueFull:
                dropped.append(sub_id)
            except Exception:  # pragma: no cover — defensive
                logger.exception("broadcaster: publish failed for %d", sub_id)

        if dropped:
            logger.warning(
                "broadcaster: dropped event for %d slow subscriber(s): %s",
                len(dropped), dropped,
            )
        return delivered

    # ------------------------------------------------------------------
    # Subscribe side — called by the SSE route handler.
    # ------------------------------------------------------------------

    @contextlib.asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue]:
        """Yield a queue that receives every future event.

        Use as::

            async with broadcaster.subscribe() as q:
                while True:
                    event = await q.get()
                    ...

        The queue is automatically removed from the fan-out table on
        context exit, even if an exception propagates.
        """
        if self._closed:
            # Still yield a queue so callers don't have to special-case;
            # it just never receives events.
            q: asyncio.Queue = asyncio.Queue(maxsize=self._queue_size)
            try:
                yield q
            finally:
                pass
            return

        q = asyncio.Queue(maxsize=self._queue_size)
        async with self._lock:
            sub_id = self._next_id
            self._next_id += 1
            self._subscribers[sub_id] = q
        logger.debug("broadcaster: subscribed %d (total=%d)", sub_id, len(self._subscribers))
        try:
            yield q
        finally:
            async with self._lock:
                self._subscribers.pop(sub_id, None)
            logger.debug(
                "broadcaster: unsubscribed %d (total=%d)",
                sub_id, len(self._subscribers),
            )

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def subscriber_count(self) -> int:
        return len(self._subscribers)

    async def close(self) -> None:
        """Mark the broadcaster closed and wake all subscribers.

        Called from ``ServiceContainer.shutdown()``. After close, no
        further events will be published; subscribers that block on
        ``queue.get()`` will need to time out or receive a sentinel
        ``None`` which we push here.
        """
        self._closed = True
        async with self._lock:
            subs = list(self._subscribers.values())
            self._subscribers.clear()
        for q in subs:
            # Best-effort: wake any awaiting `queue.get()`.
            try:
                q.put_nowait(None)
            except asyncio.QueueFull:  # pragma: no cover
                pass


__all__ = ["IncidentBroadcaster", "DEFAULT_QUEUE_SIZE"]
