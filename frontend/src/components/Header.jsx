/**
 * P3.1-full — Top app bar with mode badge and refresh button.
 */
import React from "react";
import { c } from "../theme";
import { Badge } from "./ui";

export default function Header({ status, onRefresh, streamConnected }) {
  const modeColor =
    status?.mode === "ACTIVE"
      ? c.green
      : status?.mode === "AUDIT"
      ? c.orange
      : c.red;
  return (
    <header
      style={{
        background: c.surface,
        borderBottom: `1px solid ${c.border}`,
        padding: "14px 28px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        position: "sticky",
        top: 0,
        zIndex: 100,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
        <span style={{ fontSize: "26px" }}>🛡️</span>
        <div>
          <div
            style={{
              fontSize: "18px",
              fontWeight: 800,
              color: c.text,
              letterSpacing: "-0.5px",
            }}
          >
            Sentry
          </div>
          <div
            style={{
              fontSize: "11px",
              color: c.textFaint,
              fontWeight: 500,
            }}
          >
            Self-Healing Server Monitor
          </div>
        </div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        {streamConnected !== undefined && (
          <Badge color={streamConnected ? c.green : c.textFaint} small>
            {streamConnected ? "● live" : "○ poll"}
          </Badge>
        )}
        {status && <Badge color={modeColor}>{status.mode}</Badge>}
        <button
          onClick={onRefresh}
          style={{
            padding: "7px 16px",
            borderRadius: "8px",
            fontSize: "12px",
            fontWeight: 600,
            background: c.surfaceAlt,
            color: c.textDim,
            border: `1px solid ${c.border}`,
          }}
        >
          ↻ Refresh
        </button>
      </div>
    </header>
  );
}
