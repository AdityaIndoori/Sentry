/**
 * P3.1 — Unified fetch client for the Sentry API.
 *
 * Handles:
 *   * Bearer-token injection (reads `import.meta.env.VITE_API_TOKEN` at
 *     build time; in dev you can also set ``localStorage.sentryToken``).
 *   * JSON parsing + status-based error throwing.
 *   * Credentials: include (so SameSite cookies work if we add them).
 *
 * Every component should go through `apiFetch()` or a wrapper rather
 * than calling `fetch()` directly — that way token / header changes
 * happen in one place.
 */

export const API_BASE = "/api";

/**
 * Resolve the bearer token at call time.
 *
 * Priority:
 *   1. ``localStorage.sentryToken`` — handy for dev; user types a token
 *      once and it sticks.
 *   2. ``import.meta.env.VITE_API_TOKEN`` — compiled into the bundle
 *      for container-baked deployments.
 *   3. ``null`` — no auth header sent (backend is in dev mode).
 */
export function getAuthToken() {
  if (typeof window !== "undefined" && window.localStorage) {
    const stored = window.localStorage.getItem("sentryToken");
    if (stored) return stored;
  }
  // Vite exposes only variables prefixed with VITE_.
  const compiled =
    typeof import.meta !== "undefined" &&
    import.meta.env &&
    import.meta.env.VITE_API_TOKEN;
  return compiled || null;
}

export function setAuthToken(token) {
  if (typeof window === "undefined" || !window.localStorage) return;
  if (token) {
    window.localStorage.setItem("sentryToken", token);
  } else {
    window.localStorage.removeItem("sentryToken");
  }
}

/**
 * Thin wrapper around ``fetch`` that adds the bearer token and
 * normalizes errors.
 *
 * @param {string} path      Path under ``API_BASE`` (e.g. "/incidents").
 * @param {object} opts
 * @param {string} [opts.method="GET"]
 * @param {object} [opts.body]          JSON-serializable body.
 * @param {AbortSignal} [opts.signal]
 * @returns {Promise<any>}              Parsed JSON (or ``null`` on 204).
 * @throws {Error}  with ``.status`` on non-2xx responses.
 */
export async function apiFetch(path, { method = "GET", body, signal } = {}) {
  const headers = { Accept: "application/json" };
  const token = getAuthToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: "include",
    signal,
  });

  if (res.status === 204) return null;

  let payload = null;
  try {
    payload = await res.json();
  } catch {
    /* non-JSON response — leave payload null */
  }

  if (!res.ok) {
    const err = new Error(
      payload?.detail || payload?.error || `HTTP ${res.status}`,
    );
    err.status = res.status;
    err.payload = payload;
    throw err;
  }
  return payload;
}

export const api = {
  health: () => apiFetch("/health"),
  ready: () => apiFetch("/ready"),
  status: () => apiFetch("/status"),
  incidents: () => apiFetch("/incidents"),
  incident: (id) => apiFetch(`/incidents/${id}`),
  trigger: (message, source = "manual") =>
    apiFetch("/trigger", { method: "POST", body: { source, message } }),
  memory: () => apiFetch("/memory"),
  tools: () => apiFetch("/tools"),
  security: () => apiFetch("/security"),
  config: () => apiFetch("/config"),
  watcherStart: () => apiFetch("/watcher/start", { method: "POST" }),
  watcherStop: () => apiFetch("/watcher/stop", { method: "POST" }),
};
