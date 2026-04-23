/**
 * P3.1-full — Top-of-page metrics row (4 stat cards).
 */
import React from "react";
import { c } from "../theme";
import { Card } from "./ui";

export default function StatusCards({ status }) {
  if (!status) return null;
  const cb = status.circuit_breaker || {};
  const pct =
    cb.max_cost_usd > 0
      ? Math.min(100, (cb.current_cost_usd / cb.max_cost_usd) * 100)
      : 0;

  const metrics = [
    {
      label: "Active Incidents",
      value: status.active_incidents || 0,
      color: status.active_incidents > 0 ? c.orange : c.green,
    },
    {
      label: "Resolved Total",
      value: status.resolved_total || 0,
      color: c.cyan,
    },
    {
      label: "API Cost",
      value: `$${(cb.current_cost_usd || 0).toFixed(4)}`,
      color: pct > 80 ? c.red : pct > 50 ? c.orange : c.green,
    },
    {
      label: "Circuit Breaker",
      value: cb.tripped ? "TRIPPED" : "OK",
      color: cb.tripped ? c.red : c.green,
    },
  ];

  return (
    <div
      data-testid="status-cards"
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(4, 1fr)",
        gap: "14px",
        marginBottom: "20px",
      }}
    >
      {metrics.map((m, i) => (
        <Card key={i} style={{ padding: "16px 18px" }}>
          <div
            style={{
              fontSize: "11px",
              fontWeight: 600,
              color: c.textDim,
              textTransform: "uppercase",
              letterSpacing: "0.5px",
              marginBottom: "6px",
            }}
          >
            {m.label}
          </div>
          <div
            style={{
              fontSize: "28px",
              fontWeight: 800,
              color: m.color,
              lineHeight: 1.1,
            }}
          >
            {m.value}
          </div>
        </Card>
      ))}
    </div>
  );
}
