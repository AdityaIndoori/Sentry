/**
 * P3.1-full — System configuration overview panel.
 */
import React from "react";
import { c } from "../theme";
import { Card, SectionTitle } from "./ui";

export default function ConfigPanel({ config }) {
  if (!config) return null;
  const providerLabel =
    { bedrock_gateway: "AWS Bedrock Gateway", anthropic: "Anthropic Direct" }[
      config.llm_provider
    ] || config.llm_provider;
  const shortModel = (config.model || "unknown")
    .replace("global.anthropic.", "")
    .replace("claude-", "Claude ")
    .replace(/-v\d+$/, "");
  const modeColor =
    config.mode === "ACTIVE"
      ? c.green
      : config.mode === "AUDIT"
      ? c.orange
      : c.red;

  return (
    <Card style={{ marginBottom: "20px" }}>
      <SectionTitle icon="⚙">System Configuration</SectionTitle>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 1fr)",
          gap: "12px",
          marginBottom: "12px",
        }}
      >
        <div
          style={{
            padding: "14px",
            borderRadius: "10px",
            background: c.bg,
            border: `1px solid ${c.border}`,
            textAlign: "center",
          }}
        >
          <div
            style={{
              fontSize: "10px",
              fontWeight: 700,
              color: c.textFaint,
              textTransform: "uppercase",
              letterSpacing: "0.5px",
              marginBottom: "6px",
            }}
          >
            LLM Provider
          </div>
          <div style={{ fontSize: "15px", fontWeight: 700, color: c.accent }}>
            {providerLabel}
          </div>
          <div
            style={{
              fontSize: "10px",
              color: c.textDim,
              marginTop: "4px",
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            {shortModel}
          </div>
        </div>
        <div
          style={{
            padding: "14px",
            borderRadius: "10px",
            background: c.bg,
            border: `1px solid ${c.border}`,
            textAlign: "center",
          }}
        >
          <div
            style={{
              fontSize: "10px",
              fontWeight: 700,
              color: c.textFaint,
              textTransform: "uppercase",
              letterSpacing: "0.5px",
              marginBottom: "6px",
            }}
          >
            Monitored Service
          </div>
          <div
            style={{
              fontSize: "13px",
              fontWeight: 700,
              color: c.cyan,
              fontFamily: "'JetBrains Mono', monospace",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {config.service_source_path || "/app/workspace"}
          </div>
          <div style={{ fontSize: "10px", color: c.textDim, marginTop: "4px" }}>
            {(config.watch_paths || []).length} watch path
            {(config.watch_paths || []).length !== 1 ? "s" : ""}
          </div>
        </div>
        <div
          style={{
            padding: "14px",
            borderRadius: "10px",
            background: c.bg,
            border: `1px solid ${modeColor}30`,
            textAlign: "center",
          }}
        >
          <div
            style={{
              fontSize: "10px",
              fontWeight: 700,
              color: c.textFaint,
              textTransform: "uppercase",
              letterSpacing: "0.5px",
              marginBottom: "6px",
            }}
          >
            Operating Mode
          </div>
          <div style={{ fontSize: "20px", fontWeight: 800, color: modeColor }}>
            {config.mode}
          </div>
          <div style={{ fontSize: "10px", color: c.textDim, marginTop: "4px" }}>
            {config.mode === "ACTIVE"
              ? "Full autonomous operation"
              : config.mode === "AUDIT"
              ? "Log only, no execution"
              : "All actions disabled"}
          </div>
        </div>
      </div>
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: "8px",
          fontSize: "11px",
          justifyContent: "center",
        }}
      >
        {[
          {
            label: "Watch Paths",
            value: (config.watch_paths || []).join(", ") || "none",
          },
          { label: "Poll Interval", value: `${config.poll_interval || 5}s` },
          { label: "Cost Limit", value: `$${config.max_cost_10min || 5}/10min` },
          { label: "Max Retries", value: config.max_retries || 3 },
          {
            label: "Restart Cooldown",
            value: `${config.restart_cooldown || 600}s`,
          },
          { label: "Log Level", value: config.log_level || "INFO" },
        ].map((item, i) => (
          <div
            key={i}
            title={String(item.value)}
            style={{
              padding: "5px 10px",
              borderRadius: "6px",
              background: c.surfaceAlt,
              border: `1px solid ${c.border}`,
              display: "flex",
              gap: "6px",
              alignItems: "center",
            }}
          >
            <span style={{ color: c.textFaint, fontWeight: 600 }}>
              {item.label}:
            </span>
            <span
              style={{
                color: c.textDim,
                fontFamily: "'JetBrains Mono', monospace",
                fontWeight: 500,
              }}
            >
              {item.value}
            </span>
          </div>
        ))}
      </div>
    </Card>
  );
}
