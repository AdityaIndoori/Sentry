"""
Escalation notifier — webhook delivery for incidents that need a human.

Why this exists
---------------
An ESCALATED incident is, by definition, one Sentry could not fix on its
own. Before this module the escalation was only visible to someone who
happened to be watching the dashboard or tailing the audit log — the
exact alert-fatigue failure mode the project exists to eliminate. A
self-healing monitor that silently gives up is worse than a pager,
because the operator has been trained to *not* watch.

``WebhookNotifier`` POSTs a compact JSON payload to an operator-supplied
URL whenever an incident reaches a terminal state worth human attention
(ESCALATED always; RESOLVED optionally for audit trails). The payload
shape is deliberately Slack/Discord/PagerDuty-events-API friendly: a
``text`` summary field plus the structured incident dict.

Design constraints
------------------
* **Fire-and-forget**: notification must NEVER block or fail the
  orchestrator hot path. Delivery happens in a background task with a
  bounded timeout and swallowed exceptions (logged + counted).
* **Optional dependency-free**: uses ``httpx`` which is already a core
  dependency (FastAPI test client). No new requirements.
* **Disabled by default**: when ``NOTIFY_WEBHOOK_URL`` is unset the
  notifier is not even constructed (factory wires ``None``).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_SECONDS = 5.0


class WebhookNotifier:
    """POSTs incident lifecycle notifications to a webhook URL."""

    def __init__(
        self,
        webhook_url: str,
        *,
        notify_resolved: bool = False,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._url = webhook_url
        self._notify_resolved = notify_resolved
        self._timeout = timeout_seconds
        # Keep handles so shutdown can drain; tasks remove themselves.
        self._inflight: set[asyncio.Task[None]] = set()
        # Simple delivery stats for /api/status + tests.
        self.sent_count = 0
        self.error_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def should_notify(self, state: str) -> bool:
        """Whether this terminal ``state`` warrants a notification."""
        if state == "escalated":
            return True
        return state == "resolved" and self._notify_resolved

    def notify_incident(self, incident: Any) -> None:
        """Schedule a fire-and-forget notification for ``incident``.

        Never raises. Never blocks. Safe to call from the orchestrator's
        ``finally`` block.
        """
        try:
            state = incident.state.value if hasattr(incident.state, "value") else str(incident.state)
            if not self.should_notify(state):
                return
            payload = self._build_payload(incident, state)
            task = asyncio.get_running_loop().create_task(
                self._deliver(payload), name=f"sentry-notify-{incident.id}"
            )
            self._inflight.add(task)
            task.add_done_callback(self._inflight.discard)
        except RuntimeError:
            # No running loop (sync test context) — deliver inline, best-effort.
            try:
                state = incident.state.value if hasattr(incident.state, "value") else str(incident.state)
                asyncio.run(self._deliver(self._build_payload(incident, state)))
            except Exception:  # pragma: no cover — defensive
                logger.exception("notifier: inline delivery failed")
        except Exception:  # pragma: no cover — defensive
            logger.exception("notifier: failed to schedule notification")

    async def close(self) -> None:
        """Wait briefly for in-flight deliveries, then cancel stragglers."""
        pending = [t for t in self._inflight if not t.done()]
        if not pending:
            return
        _done, still_pending = await asyncio.wait(pending, timeout=self._timeout)
        for t in still_pending:
            t.cancel()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_payload(self, incident: Any, state: str) -> dict[str, Any]:
        symptom = (incident.symptom or "")[:300]
        root_cause = (incident.root_cause or "unknown")[:300]
        fix = (incident.fix_applied or "none")[:300]
        emoji = "🚨" if state == "escalated" else "✅"
        text = (
            f"{emoji} Sentry incident {incident.id} {state.upper()}\n"
            f"Symptom: {symptom}\n"
            f"Root cause: {root_cause}\n"
            f"Fix: {fix}\n"
            f"Retries: {incident.retry_count} | Cost: ${incident.cost_usd:.4f}"
        )
        return {
            "text": text,
            "incident": {
                "id": incident.id,
                "state": state,
                "severity": incident.severity.value
                if hasattr(incident.severity, "value")
                else str(incident.severity),
                "symptom": symptom,
                "root_cause": root_cause,
                "fix_applied": fix,
                "retry_count": incident.retry_count,
                "cost_usd": incident.cost_usd,
            },
            "ts": datetime.now(UTC).isoformat(),
        }

    async def _deliver(self, payload: dict[str, Any]) -> None:
        delivered = False
        try:
            import httpx

            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(self._url, json=payload)
                if resp.status_code >= 400:
                    self.error_count += 1
                    logger.warning(
                        "notifier: webhook returned %s for incident %s",
                        resp.status_code,
                        payload.get("incident", {}).get("id"),
                    )
                else:
                    self.sent_count += 1
                    delivered = True
        except Exception as exc:
            self.error_count += 1
            logger.warning("notifier: webhook delivery failed: %s", exc)
        # Metrics are best-effort and optional.
        try:
            from backend.shared.metrics import inc_notification

            inc_notification(success=delivered)
        except Exception:  # pragma: no cover
            pass


__all__ = ["WebhookNotifier"]
