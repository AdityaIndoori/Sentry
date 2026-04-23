/**
 * P3.1-full — Start/Stop button for the log watcher.
 */
import React from "react";
import { c } from "../theme";
import { api } from "../api/client";

export default function WatcherControls({ running, onToggle }) {
  const handleToggle = async () => {
    try {
      if (running) {
        await api.watcherStop();
      } else {
        await api.watcherStart();
      }
      if (onToggle) onToggle();
    } catch (e) {
      console.error("watcher toggle failed", e);
    }
  };

  return (
    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
      <span
        aria-label={running ? "watching" : "stopped"}
        style={{
          width: 8,
          height: 8,
          borderRadius: "50%",
          background: running ? c.green : c.red,
          boxShadow: running ? `0 0 8px ${c.green}` : "none",
        }}
      />
      <span style={{ fontSize: "12px", color: c.textDim }}>
        {running ? "Watching" : "Stopped"}
      </span>
      <button
        onClick={handleToggle}
        style={{
          padding: "5px 14px",
          borderRadius: "7px",
          fontSize: "11px",
          fontWeight: 600,
          background: running ? c.redDim : c.greenDim,
          color: running ? c.red : c.green,
          border: `1px solid ${running ? c.red + "40" : c.green + "40"}`,
        }}
      >
        {running ? "⏹ Stop" : "▶ Start"}
      </button>
    </div>
  );
}
