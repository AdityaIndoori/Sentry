/**
 * P4.3 — apiFetch + token-storage tests.
 *
 * The fetch wrapper is the single chokepoint for every outbound call
 * from the UI, so regressions here potentially affect every feature.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { apiFetch, getAuthToken, setAuthToken, api } from "../client";

describe("getAuthToken", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("returns null when nothing is configured", () => {
    expect(getAuthToken()).toBeNull();
  });

  it("prefers localStorage over the compiled env var", () => {
    window.localStorage.setItem("sentryToken", "dev-token");
    expect(getAuthToken()).toBe("dev-token");
  });
});

describe("setAuthToken", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("stores the token under sentryToken", () => {
    setAuthToken("abc");
    expect(window.localStorage.getItem("sentryToken")).toBe("abc");
  });

  it("clears the token when passed a falsy value", () => {
    window.localStorage.setItem("sentryToken", "abc");
    setAuthToken(null);
    expect(window.localStorage.getItem("sentryToken")).toBeNull();
  });
});

describe("apiFetch", () => {
  let origFetch;

  beforeEach(() => {
    window.localStorage.clear();
    origFetch = window.fetch;
  });

  afterEach(() => {
    window.fetch = origFetch;
    vi.restoreAllMocks();
  });

  const mockResponse = (opts = {}) => {
    const { status = 200, body = { ok: true } } = opts;
    return {
      status,
      ok: status >= 200 && status < 300,
      json: async () => body,
    };
  };

  it("issues a GET to /api/<path> with JSON Accept header", async () => {
    window.fetch = vi.fn().mockResolvedValue(mockResponse({ body: { x: 1 } }));
    const data = await apiFetch("/status");
    expect(data).toEqual({ x: 1 });
    const [url, init] = window.fetch.mock.calls[0];
    expect(url).toBe("/api/status");
    expect(init.method).toBe("GET");
    expect(init.headers.Accept).toBe("application/json");
    expect(init.headers.Authorization).toBeUndefined();
  });

  it("injects the Bearer token when localStorage has one", async () => {
    setAuthToken("sk_test");
    window.fetch = vi.fn().mockResolvedValue(mockResponse());
    await apiFetch("/status");
    const [, init] = window.fetch.mock.calls[0];
    expect(init.headers.Authorization).toBe("Bearer sk_test");
  });

  it("serializes a JSON body and sets Content-Type", async () => {
    window.fetch = vi.fn().mockResolvedValue(mockResponse({ body: null }));
    await apiFetch("/trigger", {
      method: "POST",
      body: { source: "manual", message: "hi" },
    });
    const [, init] = window.fetch.mock.calls[0];
    expect(init.method).toBe("POST");
    expect(init.headers["Content-Type"]).toBe("application/json");
    expect(JSON.parse(init.body)).toEqual({
      source: "manual",
      message: "hi",
    });
  });

  it("throws with .status on non-2xx responses", async () => {
    window.fetch = vi.fn().mockResolvedValue(
      mockResponse({ status: 401, body: { detail: "Unauthorized" } }),
    );
    await expect(apiFetch("/incidents")).rejects.toMatchObject({
      status: 401,
      message: "Unauthorized",
    });
  });

  it("returns null on 204 without calling json()", async () => {
    const res = {
      status: 204,
      ok: true,
      json: vi.fn(),
    };
    window.fetch = vi.fn().mockResolvedValue(res);
    const data = await apiFetch("/watcher/stop", { method: "POST" });
    expect(data).toBeNull();
    expect(res.json).not.toHaveBeenCalled();
  });

  it("falls back to HTTP <status> when body has no detail", async () => {
    window.fetch = vi.fn().mockResolvedValue(
      mockResponse({ status: 500, body: {} }),
    );
    await expect(apiFetch("/incidents")).rejects.toMatchObject({
      status: 500,
      message: "HTTP 500",
    });
  });
});

describe("api surface", () => {
  let origFetch;

  beforeEach(() => {
    origFetch = window.fetch;
    window.fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({}),
    });
  });

  afterEach(() => {
    window.fetch = origFetch;
  });

  it("health hits /api/health", async () => {
    await api.health();
    expect(window.fetch.mock.calls[0][0]).toBe("/api/health");
  });

  it("trigger posts source + message", async () => {
    await api.trigger("boom");
    const [, init] = window.fetch.mock.calls[0];
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body);
    expect(body.source).toBe("manual");
    expect(body.message).toBe("boom");
  });

  it("watcherStart posts to /api/watcher/start", async () => {
    await api.watcherStart();
    expect(window.fetch.mock.calls[0][0]).toBe("/api/watcher/start");
    expect(window.fetch.mock.calls[0][1].method).toBe("POST");
  });
});
