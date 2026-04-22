/**
 * P3.1 — useIncidentStream: React hook for the /api/stream/incidents SSE feed.
 *
 * Replaces the legacy 5-second polling loop. Opens an ``EventSource``
 * against the P2.4 backend route and emits the latest event to the
 * caller, plus a rolling list of the last ``limit`` events.
 *
 * Auth note: ``EventSource`` does NOT support custom headers (no
 * ``Authorization: Bearer …``). In production deployments that enable
 * auth, the reverse proxy is expected to inject the header — this is
 * the same constraint as every other SSE implementation. When auth is
 * disabled (dev mode / empty token registry) the stream opens freely.
 *
 * Usage:
 *
 *     const { last, events, connected, error } = useIncidentStream();
 *     useEffect(() => {
 *       if (last?.kind === "incident.updated") refetchIncidents();
 *     }, [last]);
 */

import { useEffect, useRef, useState, useCallback } from "react";

const STREAM_PATH = "/api/stream/incidents";
const DEFAULT_LIMIT = 50;
const RECONNECT_BACKOFF_MS = [500, 1000, 2000, 4000, 8000];

export function useIncidentStream({ limit = DEFAULT_LIMIT } = {}) {
  const [connected, setConnected] = useState(false);
  const [last, setLast] = useState(null);
  const [events, setEvents] = useState([]);
  const [error, setError] = useState(null);
  const esRef = useRef(null);
  const retryCountRef = useRef(0);
  const closedByUserRef = useRef(false);

  const pushEvent = useCallback(
    (evt) => {
      setLast(evt);
      setEvents((prev) => {
        const next = [...prev, evt];
        if (next.length > limit) next.splice(0, next.length - limit);
        return next;
      });
    },
    [limit],
  );

  const connect = useCallback(() => {
    if (closedByUserRef.current) return;
    const es = new EventSource(STREAM_PATH, { withCredentials: true });
    esRef.current = es;

    es.addEventListener("open", () => {
      setConnected(true);
      setError(null);
      retryCountRef.current = 0;
    });

    // Our backend emits an "event: connected" hello frame.
    es.addEventListener("connected", () => {
      setConnected(true);
    });

    // Backend publishes "incident.created" and "incident.updated".
    const handle = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        pushEvent(data);
      } catch (e) {
        // Don't kill the stream on a single malformed message.
        console.warn("useIncidentStream: malformed event", e);
      }
    };
    es.addEventListener("incident.created", handle);
    es.addEventListener("incident.updated", handle);
    // Safety catch-all — some proxies rewrite the event name.
    es.addEventListener("message", handle);

    es.addEventListener("error", () => {
      setConnected(false);
      setError("stream disconnected");
      es.close();
      esRef.current = null;
      if (!closedByUserRef.current) {
        const idx = Math.min(
          retryCountRef.current,
          RECONNECT_BACKOFF_MS.length - 1,
        );
        const delay = RECONNECT_BACKOFF_MS[idx];
        retryCountRef.current += 1;
        setTimeout(connect, delay);
      }
    });
  }, [pushEvent]);

  useEffect(() => {
    closedByUserRef.current = false;
    connect();
    return () => {
      closedByUserRef.current = true;
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
    };
  }, [connect]);

  return { connected, last, events, error };
}
