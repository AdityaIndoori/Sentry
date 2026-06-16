/**
 * "Connect a service" onboarding panel.
 *
 * The seamless first-run experience: the user names a service, clicks
 * "Generate", and immediately gets a one-line ``curl`` (and a Docker
 * sidecar snippet) pre-filled with their fresh ingestion token. As soon
 * as their logs start flowing, matching error lines appear as incidents
 * in the dashboard below.
 *
 * The raw token is shown EXACTLY ONCE (right after minting) — the API
 * only ever returns the hash afterwards — so we surface a clear "copy it
 * now" affordance.
 */
import React, { useCallback, useEffect, useState } from "react";

import { api } from "../api/client";
import { c } from "../theme";

export default function ConnectService() {
  const [tokens, setTokens] = useState([]);
  const [serviceName, setServiceName] = useState("");
  const [minting, setMinting] = useState(false);
  const [freshToken, setFreshToken] = useState(null); // { token, service_name }
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const resp = await api.listIngestTokens();
      setTokens(resp.tokens || []);
    } catch (err) {
      setError(err.message || "Failed to load tokens");
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onMint(e) {
    e.preventDefault();
    setError("");
    setMinting(true);
    try {
      const resp = await api.mintIngestToken(serviceName.trim());
      setFreshToken(resp);
      setServiceName("");
      await refresh();
    } catch (err) {
      setError(err.message || "Failed to generate token");
    } finally {
      setMinting(false);
    }
  }

  async function onRevoke(id) {
    try {
      await api.revokeIngestToken(id);
      await refresh();
    } catch (err) {
      setError(err.message || "Failed to revoke token");
    }
  }

  const origin =
    typeof window !== "undefined" ? window.location.origin : "https://YOUR_SENTRY_HOST";

  return (
    <section
      style={{
        background: c.surface,
        border: `1px solid ${c.border}`,
        borderRadius: "12px",
        padding: "20px 22px",
        marginBottom: "20px",
      }}
    >
      <h2
        style={{
          margin: "0 0 4px",
          fontSize: "15px",
          fontWeight: 700,
          color: c.text,
        }}
      >
        🔌 Connect a service
      </h2>
      <p style={{ margin: "0 0 16px", fontSize: "12px", color: c.textDim }}>
        Generate an ingestion token, drop it into your log shipper, and Sentry
        starts triaging the errors it sees — automatically.
      </p>

      <form onSubmit={onMint} style={{ display: "flex", gap: "10px", marginBottom: "16px" }}>
        <input
          value={serviceName}
          onChange={(e) => setServiceName(e.target.value)}
          placeholder="Service name (e.g. prod-api)"
          style={{
            flex: 1,
            padding: "9px 12px",
            borderRadius: "8px",
            border: `1px solid ${c.border}`,
            background: c.bg,
            color: c.text,
            fontSize: "13px",
            outline: "none",
          }}
        />
        <button
          type="submit"
          disabled={minting}
          style={{
            padding: "9px 18px",
            borderRadius: "8px",
            border: "none",
            cursor: minting ? "wait" : "pointer",
            fontSize: "13px",
            fontWeight: 700,
            color: "#fff",
            background: c.accent,
          }}
        >
          {minting ? "Generating…" : "Generate token"}
        </button>
      </form>

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

      {freshToken && (
        <FreshTokenCard
          token={freshToken.token}
          serviceName={freshToken.service_name}
          origin={origin}
          onDismiss={() => setFreshToken(null)}
        />
      )}

      {/* Existing tokens */}
      {tokens.length > 0 && (
        <div style={{ marginTop: freshToken ? "16px" : 0 }}>
          <div
            style={{
              fontSize: "11px",
              textTransform: "uppercase",
              letterSpacing: "0.5px",
              color: c.textFaint,
              marginBottom: "8px",
            }}
          >
            Connected services
          </div>
          {tokens.map((t) => (
            <div
              key={t.id}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "10px 12px",
                background: c.bg,
                border: `1px solid ${c.border}`,
                borderRadius: "8px",
                marginBottom: "8px",
              }}
            >
              <div>
                <div style={{ fontSize: "13px", color: c.text, fontWeight: 600 }}>
                  {t.service_name || "(unnamed)"}
                </div>
                <div style={{ fontSize: "11px", color: c.textFaint }}>
                  id {t.id} ·{" "}
                  {t.last_used_at
                    ? `last seen ${new Date(t.last_used_at).toLocaleString()}`
                    : "no logs received yet"}
                </div>
              </div>
              <button
                onClick={() => onRevoke(t.id)}
                style={{
                  padding: "6px 12px",
                  borderRadius: "7px",
                  border: `1px solid ${c.border}`,
                  background: "transparent",
                  color: c.red,
                  cursor: "pointer",
                  fontSize: "12px",
                }}
              >
                Revoke
              </button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function FreshTokenCard({ token, serviceName, origin, onDismiss }) {
  const curl = `curl -X POST ${origin}/api/ingest \\
  -H "X-Ingest-Token: ${token}" \\
  -H "Content-Type: application/json" \\
  -d '{"lines": ["ERROR: something went wrong"]}'`;

  return (
    <div
      style={{
        background: c.greenDim,
        border: `1px solid ${c.green}`,
        borderRadius: "10px",
        padding: "16px",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "10px",
        }}
      >
        <strong style={{ color: c.green, fontSize: "13px" }}>
          ✅ Token created for “{serviceName || "service"}”
        </strong>
        <button
          onClick={onDismiss}
          style={{
            background: "transparent",
            border: "none",
            color: c.textDim,
            cursor: "pointer",
            fontSize: "16px",
          }}
        >
          ✕
        </button>
      </div>
      <p style={{ margin: "0 0 10px", fontSize: "11px", color: c.textDim }}>
        Copy this now — it is shown only once. Point your log shipper at the
        snippet below and matching errors become incidents automatically.
      </p>

      <CopyBlock label="Ingestion token" value={token} />
      <CopyBlock label="Quick test (curl)" value={curl} multiline />
    </div>
  );
}

function CopyBlock({ label, value, multiline }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    if (navigator?.clipboard) {
      navigator.clipboard.writeText(value).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      });
    }
  }
  return (
    <div style={{ marginBottom: "10px" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginBottom: "4px",
        }}
      >
        <span style={{ fontSize: "11px", color: c.textFaint }}>{label}</span>
        <button
          onClick={copy}
          style={{
            background: "transparent",
            border: "none",
            color: c.accent,
            cursor: "pointer",
            fontSize: "11px",
            fontWeight: 600,
          }}
        >
          {copied ? "Copied!" : "Copy"}
        </button>
      </div>
      <pre
        style={{
          margin: 0,
          padding: "10px 12px",
          background: c.bg,
          border: `1px solid ${c.border}`,
          borderRadius: "8px",
          color: c.text,
          fontSize: "12px",
          fontFamily: "ui-monospace, 'SF Mono', Menlo, monospace",
          whiteSpace: multiline ? "pre" : "nowrap",
          overflowX: "auto",
        }}
      >
        {value}
      </pre>
    </div>
  );
}
