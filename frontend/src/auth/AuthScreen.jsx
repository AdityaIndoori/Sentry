/**
 * Login / Signup screen — shown when there is no authenticated session.
 *
 * A single centered card that toggles between "Log in" and "Sign up".
 * On success the AuthContext flips ``status`` to ``authenticated`` and
 * the app swaps this screen out for the dashboard.
 */
import React, { useState } from "react";

import { useAuth } from "./AuthContext";
import { c } from "../theme";

export default function AuthScreen() {
  const { login, signup, cfMode } = useAuth();
  const [mode, setMode] = useState("login"); // "login" | "signup"
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const isSignup = mode === "signup";

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    const res = isSignup
      ? await signup(email, password, "")
      : await login(email, password);
    setBusy(false);
    if (!res.ok) setError(res.error);
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        background: c.bg,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontFamily:
          "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif",
        padding: "24px",
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: "400px",
          background: c.surface,
          border: `1px solid ${c.border}`,
          borderRadius: "14px",
          padding: "32px",
          boxShadow: "0 12px 40px rgba(0,0,0,0.4)",
        }}
      >
        <div style={{ textAlign: "center", marginBottom: "24px" }}>
          <div style={{ fontSize: "32px", marginBottom: "6px" }}>🛡️</div>
          <h1
            style={{
              margin: 0,
              fontSize: "22px",
              fontWeight: 700,
              color: c.text,
              letterSpacing: "-0.4px",
            }}
          >
            Sentry
          </h1>
          <p style={{ margin: "6px 0 0", fontSize: "13px", color: c.textDim }}>
            Self-healing monitor for your services
          </p>
        </div>

        {/* Cloudflare Access mode: no password form — defer to the edge. */}
        {cfMode ? (
          <div>
            <p style={{ fontSize: "13px", color: c.textDim, textAlign: "center", lineHeight: 1.6 }}>
              This deployment is protected by{" "}
              <strong style={{ color: c.text }}>Cloudflare Access</strong>. Sign in
              with your organization identity to continue.
            </p>
            <button
              type="button"
              onClick={() => window.location.reload()}
              style={{
                width: "100%",
                marginTop: "16px",
                padding: "11px",
                borderRadius: "9px",
                border: "none",
                cursor: "pointer",
                fontSize: "14px",
                fontWeight: 700,
                color: "#fff",
                background: c.accent,
              }}
            >
              Continue with Cloudflare Access
            </button>
          </div>
        ) : (
        <>
        {/* mode toggle */}
        <div
          style={{
            display: "flex",
            background: c.bg,
            borderRadius: "10px",
            padding: "4px",
            marginBottom: "22px",
            border: `1px solid ${c.border}`,
          }}
        >
          {["login", "signup"].map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => {
                setMode(m);
                setError("");
              }}
              style={{
                flex: 1,
                padding: "8px",
                borderRadius: "7px",
                border: "none",
                cursor: "pointer",
                fontSize: "13px",
                fontWeight: 600,
                color: mode === m ? "#fff" : c.textDim,
                background: mode === m ? c.accent : "transparent",
                transition: "all 0.15s",
              }}
            >
              {m === "login" ? "Log in" : "Sign up"}
            </button>
          ))}
        </div>

        <form onSubmit={onSubmit}>
          <Field
            label="Email"
            type="email"
            value={email}
            onChange={setEmail}
            placeholder="you@company.com"
            autoFocus
          />
          <Field
            label="Password"
            type="password"
            value={password}
            onChange={setPassword}
            placeholder={isSignup ? "At least 8 characters" : "••••••••"}
          />

          {error && (
            <div
              style={{
                background: c.redDim,
                border: `1px solid ${c.red}`,
                color: c.red,
                borderRadius: "8px",
                padding: "9px 12px",
                fontSize: "12px",
                marginBottom: "14px",
              }}
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={busy || !email || !password}
            style={{
              width: "100%",
              padding: "11px",
              borderRadius: "9px",
              border: "none",
              cursor: busy ? "wait" : "pointer",
              fontSize: "14px",
              fontWeight: 700,
              color: "#fff",
              background: busy ? c.accentDim : c.accent,
              opacity: !email || !password ? 0.55 : 1,
            }}
          >
            {busy
              ? "Please wait…"
              : isSignup
                ? "Create account"
                : "Log in"}
          </button>
        </form>

        <p
          style={{
            marginTop: "18px",
            fontSize: "11px",
            color: c.textFaint,
            textAlign: "center",
            lineHeight: 1.5,
          }}
        >
          {isSignup
            ? "Free to start. Connect your first service in under a minute."
            : "Welcome back. Your incidents are waiting."}
        </p>
        </>
        )}
      </div>
    </div>
  );
}

function Field({ label, type, value, onChange, placeholder, autoFocus }) {
  return (
    <label style={{ display: "block", marginBottom: "14px" }}>
      <span
        style={{
          display: "block",
          fontSize: "12px",
          fontWeight: 600,
          color: c.textDim,
          marginBottom: "6px",
        }}
      >
        {label}
      </span>
      <input
        type={type}
        value={value}
        autoFocus={autoFocus}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          width: "100%",
          boxSizing: "border-box",
          padding: "10px 12px",
          borderRadius: "8px",
          border: `1px solid ${c.border}`,
          background: c.bg,
          color: c.text,
          fontSize: "14px",
          outline: "none",
        }}
      />
    </label>
  );
}
