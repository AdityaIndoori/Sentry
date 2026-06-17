/**
 * SaaS auth context — supports two modes:
 *
 *  1. **Cloudflare Access** (``cf_access_enabled``): the browser is
 *     already authenticated at Cloudflare's edge, which injects the
 *     ``Cf-Access-Jwt-Assertion`` header on every request. We just call
 *     ``/api/auth/me`` to load the identity; there is NO password screen.
 *     Logout redirects to Cloudflare's ``/cdn-cgi/access/logout``.
 *
 *  2. **Password** (default / local dev): the homegrown email+password
 *     flow with a session bearer token stored in ``localStorage``.
 *
 * The mode is discovered once via ``/api/auth/config`` so the same build
 * works in both deployments.
 */
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";

import { api, getAuthToken, setAuthToken } from "../api/client";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => getAuthToken());
  const [account, setAccount] = useState(null);
  const [status, setStatus] = useState("loading"); // loading|anonymous|authenticated
  const [cfMode, setCfMode] = useState(false);
  const [logoutUrl, setLogoutUrl] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function hydrate() {
      // Discover the auth mode first.
      let cfEnabled = false;
      try {
        const cfg = await api.authConfig();
        cfEnabled = !!cfg.cf_access_enabled;
        if (!cancelled) {
          setCfMode(cfEnabled);
          setLogoutUrl(cfg.logout_url || "");
        }
      } catch {
        /* config endpoint unavailable — assume password mode */
      }

      if (cfEnabled) {
        // Cloudflare Access already authenticated the browser at the
        // edge; the JWT rides along automatically. Just load identity.
        try {
          const me = await api.me();
          if (!cancelled) {
            setAccount(me);
            setStatus("authenticated");
          }
        } catch {
          // Not signed in at the edge yet — bounce to Access login by
          // reloading the protected origin (Cloudflare intercepts).
          if (!cancelled) setStatus("anonymous");
        }
        return;
      }

      // Password mode: validate any persisted bearer token.
      if (!token) {
        if (!cancelled) setStatus("anonymous");
        return;
      }
      try {
        const me = await api.me();
        if (!cancelled) {
          setAccount(me);
          setStatus("authenticated");
        }
      } catch {
        if (!cancelled) {
          setAuthToken(null);
          setToken(null);
          setAccount(null);
          setStatus("anonymous");
        }
      }
    }
    hydrate();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const _establish = useCallback((resp) => {
    setAuthToken(resp.token);
    setToken(resp.token);
    setAccount(resp.account || null);
    setStatus("authenticated");
  }, []);

  const login = useCallback(
    async (email, password) => {
      try {
        _establish(await api.login(email, password));
        return { ok: true };
      } catch (err) {
        return { ok: false, error: err.message || "Login failed" };
      }
    },
    [_establish],
  );

  const signup = useCallback(
    async (email, password, displayName) => {
      try {
        _establish(await api.signup(email, password, displayName));
        return { ok: true };
      } catch (err) {
        return { ok: false, error: err.message || "Signup failed" };
      }
    },
    [_establish],
  );

  const logout = useCallback(() => {
    // Clear the persisted bearer token FIRST so any subsequent page
    // load (or in-flight ``api.me`` retry) sees an anonymous session.
    setAuthToken(null);
    setToken(null);
    setAccount(null);
    setStatus("anonymous");
    if (typeof window !== "undefined") {
      if (cfMode) {
        // Cloudflare Access: log out at the edge via the *app's own*
        // origin logout endpoint (``/cdn-cgi/access/logout``). Hitting
        // the app-origin path (rather than the team-domain
        // ``…cloudflareaccess.com/cdn-cgi/access/logout``) clears the
        // app's Access cookie AND guarantees that the follow-up visit to
        // the app is re-challenged immediately — otherwise the SPA would
        // momentarily re-render the (now broken, 401-ing) dashboard until
        // a manual refresh, which is exactly the bug users hit.
        //
        // We use ``replace`` so the authenticated dashboard URL doesn't
        // linger in history (Back shouldn't return to a half-dead view),
        // and ``returnTo=/`` so Cloudflare bounces straight to the login
        // challenge for the app root instead of its bare "logged out"
        // splash.
        const origin = window.location.origin;
        const back = encodeURIComponent(origin + "/");
        window.location.replace(
          `${origin}/cdn-cgi/access/logout?returnTo=${back}`,
        );
        return;
      }
      // Password mode: do NOT reload. The state updates above already
      // swap the dashboard out for <AuthScreen>. A ``window.location
      // .reload()`` here was unreliable (the in-memory React tree could
      // re-render the authenticated view before the navigation settled,
      // leaving the user apparently still logged in), so we simply let
      // React re-render from the now-cleared auth state.
    }
  }, [cfMode]);



  const value = {
    token,
    account,
    status,
    cfMode,
    logoutUrl,
    isAuthenticated: status === "authenticated",
    login,
    signup,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (ctx === null) {
    throw new Error("useAuth must be used within an <AuthProvider>");
  }
  return ctx;
}
