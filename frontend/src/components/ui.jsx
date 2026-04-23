/**
 * P3.1-full — Tiny presentational primitives (Badge, Spinner, Card,
 * SectionTitle, InfoBlock) shared across the new component tree.
 */

import React from "react";
import { c } from "../theme";

export function Badge({ color, children, small }) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "4px",
        padding: small ? "2px 8px" : "4px 12px",
        borderRadius: "6px",
        fontSize: small ? "10px" : "11px",
        fontWeight: 600,
        letterSpacing: "0.3px",
        background: `${color}18`,
        color,
        border: `1px solid ${color}30`,
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

export function Spinner({ size = 14 }) {
  return (
    <span
      style={{
        display: "inline-block",
        width: size,
        height: size,
        borderRadius: "50%",
        border: `2px solid ${c.border}`,
        borderTopColor: c.accent,
        animation: "spin 0.8s linear infinite",
      }}
    />
  );
}

export function Card({ children, style, className }) {
  return (
    <div
      className={className}
      style={{
        background: c.surface,
        borderRadius: "14px",
        border: `1px solid ${c.border}`,
        padding: "20px",
        transition: "border-color 0.25s, box-shadow 0.25s",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

export function SectionTitle({ icon, children, right }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        marginBottom: "16px",
      }}
    >
      <div
        style={{
          fontSize: "12px",
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.8px",
          color: c.textDim,
          display: "flex",
          alignItems: "center",
          gap: "8px",
        }}
      >
        {icon && <span style={{ fontSize: "14px" }}>{icon}</span>}
        {children}
      </div>
      {right}
    </div>
  );
}

export function InfoBlock({ icon, title, color, children }) {
  return (
    <div
      style={{
        padding: "10px 12px",
        borderRadius: "8px",
        background: c.bg,
        marginBottom: "8px",
        border: `1px solid ${c.border}`,
      }}
    >
      <div
        style={{
          fontSize: "10px",
          fontWeight: 700,
          color: color || c.textDim,
          textTransform: "uppercase",
          letterSpacing: "0.3px",
          marginBottom: "4px",
          display: "flex",
          alignItems: "center",
          gap: "4px",
        }}
      >
        {icon} {title}
      </div>
      <div
        style={{
          fontSize: "12px",
          lineHeight: 1.6,
          color: c.textDim,
          wordBreak: "break-word",
        }}
      >
        {children}
      </div>
    </div>
  );
}

export function GlobalStyles() {
  return (
    <style>{`
      * { box-sizing: border-box; margin: 0; padding: 0; }
      body { margin: 0; background: ${c.bg}; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
      ::-webkit-scrollbar { width: 5px; }
      ::-webkit-scrollbar-track { background: transparent; }
      ::-webkit-scrollbar-thumb { background: ${c.border}; border-radius: 3px; }
      input:focus { border-color: ${c.accent} !important; outline: none; }
      button { cursor: pointer; border: none; font-family: inherit; }
      button:hover { opacity: 0.92; }
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
      @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
      @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
      @keyframes slideDown { from { opacity: 0; max-height: 0; } to { opacity: 1; max-height: 2000px; } }
      @keyframes spin { to { transform: rotate(360deg); } }
      .fade-in { animation: fadeIn 0.35s ease-out; }
      .pulse { animation: pulse 1.8s ease-in-out infinite; }
    `}</style>
  );
}

export function formatDuration(start, end) {
  const ms = end - start;
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${m}m ${rem}s`;
}
