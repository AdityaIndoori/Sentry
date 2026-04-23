/**
 * P3.1-full — Manual event trigger form.
 */
import React, { useState } from "react";
import { c } from "../theme";
import { Card, SectionTitle, Spinner } from "./ui";
import { api } from "../api/client";

export default function TriggerForm({ onTrigger }) {
  const [msg, setMsg] = useState("");
  const [sending, setSending] = useState(false);
  const [lastResult, setLastResult] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!msg.trim()) return;
    setSending(true);
    setLastResult(null);
    try {
      const data = await api.trigger(msg, "dashboard");
      setLastResult(data);
      setMsg("");
      if (onTrigger) onTrigger();
    } catch (err) {
      setLastResult({ error: err.message || String(err) });
    } finally {
      setSending(false);
    }
  };

  return (
    <Card style={{ marginBottom: "20px" }}>
      <SectionTitle icon="🚨">Manual Trigger</SectionTitle>
      <form onSubmit={handleSubmit} style={{ display: "flex", gap: "10px" }}>
        <input
          value={msg}
          onChange={(e) => setMsg(e.target.value)}
          placeholder='Paste an error: "ConnectionRefusedError: [Errno 111] Connection refused"'
          style={{
            flex: 1,
            padding: "10px 14px",
            borderRadius: "9px",
            border: `1px solid ${c.border}`,
            background: c.bg,
            color: c.text,
            fontSize: "13px",
            fontFamily: "'JetBrains Mono', monospace",
          }}
        />
        <button
          type="submit"
          disabled={sending}
          style={{
            padding: "10px 22px",
            borderRadius: "9px",
            fontWeight: 700,
            fontSize: "13px",
            background: c.accent,
            color: "#fff",
            opacity: sending ? 0.6 : 1,
          }}
        >
          {sending ? (
            <>
              <Spinner size={12} /> Processing...
            </>
          ) : (
            "🔥 Trigger"
          )}
        </button>
      </form>
      {lastResult && (
        <div
          className="fade-in"
          style={{
            marginTop: "10px",
            padding: "10px 14px",
            borderRadius: "8px",
            background: c.bg,
            fontSize: "12px",
            fontFamily: "'JetBrains Mono', monospace",
            color: c.textDim,
            maxHeight: "100px",
            overflowY: "auto",
            border: `1px solid ${c.border}`,
          }}
        >
          {lastResult.incident
            ? `✓ Incident created: ${lastResult.incident.id} — ${lastResult.incident.state}`
            : lastResult.error || "No incident created"}
        </div>
      )}
    </Card>
  );
}
