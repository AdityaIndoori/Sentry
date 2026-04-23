/**
 * P3.1-full — Tabbed active/resolved incident list with expandable cards.
 */
import React, { useState } from "react";
import { c } from "../theme";
import { Badge, Card, SectionTitle, Spinner } from "./ui";
import IncidentDetail from "./IncidentDetail";

function IncidentCard({ inc }) {
  const [expanded, setExpanded] = useState(false);
  const isActive = !["resolved", "escalated", "idle"].includes(inc.state);

  const severityColor =
    inc.severity === "critical"
      ? c.red
      : inc.severity === "high"
      ? c.orange
      : inc.severity === "medium"
      ? c.cyan
      : c.textDim;

  const stateColor =
    inc.state === "resolved"
      ? c.green
      : inc.state === "escalated"
      ? c.red
      : inc.state === "idle"
      ? c.textFaint
      : c.orange;

  const toolCalls = (inc.activity_log || []).filter(
    (a) => a.activity_type === "tool_call",
  );
  const llmCalls = (inc.activity_log || []).filter(
    (a) => a.activity_type === "llm_call",
  );

  const stateIcon =
    inc.state === "resolved"
      ? "🎉"
      : inc.state === "escalated"
      ? "🚨"
      : inc.state === "triage"
      ? "🔍"
      : inc.state === "diagnosis"
      ? "🧠"
      : inc.state === "remediation"
      ? "🔧"
      : inc.state === "verification"
      ? "✅"
      : "⏸";

  return (
    <Card
      className="fade-in"
      style={{
        marginBottom: "10px",
        borderColor: expanded
          ? `${c.accent}50`
          : isActive
          ? `${stateColor}30`
          : c.border,
        boxShadow: isActive ? `0 0 20px ${stateColor}08` : "none",
      }}
    >
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: "14px",
          cursor: "pointer",
          userSelect: "none",
        }}
      >
        <div style={{ position: "relative", flexShrink: 0 }}>
          <div
            style={{
              width: 40,
              height: 40,
              borderRadius: "10px",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: `${stateColor}15`,
              fontSize: "18px",
            }}
          >
            {stateIcon}
          </div>
          {isActive && (
            <div
              className="pulse"
              style={{
                position: "absolute",
                top: -2,
                right: -2,
                width: 10,
                height: 10,
                borderRadius: "50%",
                background: stateColor,
                border: `2px solid ${c.surface}`,
              }}
            />
          )}
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              marginBottom: "4px",
            }}
          >
            <span
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: "10px",
                color: c.textFaint,
                fontWeight: 500,
              }}
            >
              {inc.id}
            </span>
            <Badge color={stateColor}>{inc.state.toUpperCase()}</Badge>
            <Badge color={severityColor} small>
              {(inc.severity || "unknown").toUpperCase()}
            </Badge>
          </div>
          <div
            style={{
              fontSize: "13px",
              fontWeight: 500,
              color: c.text,
              lineHeight: 1.4,
              overflow: "hidden",
              textOverflow: "ellipsis",
              display: "-webkit-box",
              WebkitLineClamp: expanded ? "unset" : 2,
              WebkitBoxOrient: "vertical",
            }}
          >
            {inc.triage_result || inc.symptom}
          </div>
        </div>

        <div
          style={{
            display: "flex",
            gap: "6px",
            alignItems: "center",
            flexShrink: 0,
          }}
        >
          {toolCalls.length > 0 && (
            <span
              style={{
                fontSize: "10px",
                color: c.cyan,
                background: c.cyanDim,
                padding: "3px 8px",
                borderRadius: "12px",
                fontWeight: 600,
              }}
            >
              ⚙ {toolCalls.length} tools
            </span>
          )}
          {llmCalls.length > 0 && (
            <span
              style={{
                fontSize: "10px",
                color: c.pink,
                background: c.pinkDim,
                padding: "3px 8px",
                borderRadius: "12px",
                fontWeight: 600,
              }}
            >
              🤖 {llmCalls.length} calls
            </span>
          )}
          <span
            style={{
              fontSize: "10px",
              color: c.textFaint,
              padding: "3px 8px",
              borderRadius: "12px",
              fontWeight: 500,
              background: c.surfaceAlt,
            }}
          >
            ${(inc.cost_usd || 0).toFixed(4)}
          </span>
          <span
            style={{
              fontSize: "16px",
              color: c.textFaint,
              transition: "transform 0.25s",
              transform: expanded ? "rotate(180deg)" : "rotate(0)",
            }}
          >
            ▾
          </span>
        </div>
      </div>

      {isActive && inc.current_agent_action && !expanded && (
        <div
          className="fade-in"
          style={{
            marginTop: "10px",
            padding: "7px 12px",
            borderRadius: "8px",
            background: `${c.accent}08`,
            border: `1px solid ${c.accent}18`,
            display: "flex",
            alignItems: "center",
            gap: "8px",
            fontSize: "11px",
            color: c.accent,
            fontWeight: 500,
          }}
        >
          <Spinner size={11} />
          {inc.current_agent_action}
        </div>
      )}

      {expanded && <IncidentDetail inc={inc} />}
    </Card>
  );
}

export default function IncidentList({ incidents }) {
  const active = incidents?.active || [];
  const resolved = incidents?.resolved || [];
  const [tab, setTab] = useState("active");
  const displayList = tab === "active" ? active : resolved;

  return (
    <Card data-testid="incident-list" style={{ marginBottom: "20px" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: "16px",
        }}
      >
        <SectionTitle icon="📋">Incidents</SectionTitle>
        <div style={{ display: "flex", gap: "4px" }}>
          {[
            {
              key: "active",
              label: `Active (${active.length})`,
              color: active.length > 0 ? c.orange : c.textFaint,
            },
            {
              key: "resolved",
              label: `Resolved (${resolved.length})`,
              color: c.green,
            },
          ].map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              style={{
                padding: "5px 14px",
                borderRadius: "7px",
                fontSize: "11px",
                fontWeight: 600,
                background: tab === t.key ? `${t.color}18` : "transparent",
                color: tab === t.key ? t.color : c.textFaint,
                border: `1px solid ${
                  tab === t.key ? t.color + "40" : "transparent"
                }`,
              }}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {displayList.length === 0 ? (
        <div
          style={{
            textAlign: "center",
            padding: "48px 0",
            color: c.textFaint,
          }}
        >
          <div style={{ fontSize: "48px", marginBottom: "10px" }}>
            {tab === "active" ? "✨" : "📁"}
          </div>
          <div style={{ fontSize: "13px" }}>
            {tab === "active"
              ? "No active incidents — system is healthy"
              : "No resolved incidents yet"}
          </div>
        </div>
      ) : (
        displayList.map((inc, i) => <IncidentCard key={inc.id || i} inc={inc} />)
      )}
    </Card>
  );
}
