/**
 * P3.1-full — Expanded content of one incident card:
 *   * PhaseStepper (progress dots)
 *   * Resolution Details (InfoBlock grid)
 *   * ActivityFeed (collapsible per-row detail)
 */
import React, { useState } from "react";
import { c, PHASE_META, ACTIVITY_ICONS } from "../theme";
import { Badge, Spinner, InfoBlock, formatDuration } from "./ui";

function PhaseStepper({ phaseSummary, currentAction }) {
  const phases = ["triage", "diagnosis", "remediation", "verification"];
  return (
    <div style={{ marginBottom: "16px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
        {phases.map((phase, idx) => {
          const status = phaseSummary?.[phase] || "pending";
          const meta = PHASE_META[phase];
          const isComplete = status === "complete";
          const isActive = status === "active";
          return (
            <React.Fragment key={phase}>
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  flex: 1,
                  position: "relative",
                }}
              >
                <div
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: "50%",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: isActive ? "16px" : "14px",
                    background: isComplete
                      ? `${meta.color}25`
                      : isActive
                      ? `${meta.color}15`
                      : c.surfaceAlt,
                    border: `2px solid ${
                      isComplete ? meta.color : isActive ? meta.color : c.border
                    }`,
                    boxShadow: isActive ? `0 0 12px ${meta.color}30` : "none",
                    transition: "all 0.4s",
                    position: "relative",
                  }}
                >
                  {isActive && (
                    <div
                      className="pulse"
                      style={{
                        position: "absolute",
                        inset: -4,
                        borderRadius: "50%",
                        border: `2px solid ${meta.color}40`,
                      }}
                    />
                  )}
                  {isComplete ? (
                    <span style={{ color: meta.color }}>✓</span>
                  ) : (
                    meta.icon
                  )}
                </div>
                <div
                  style={{
                    marginTop: "6px",
                    fontSize: "10px",
                    fontWeight: 700,
                    textTransform: "uppercase",
                    letterSpacing: "0.5px",
                    color: isActive
                      ? meta.color
                      : isComplete
                      ? c.textDim
                      : c.textFaint,
                  }}
                >
                  {meta.label}
                </div>
                {isActive && (
                  <div
                    style={{
                      fontSize: "9px",
                      color: meta.color,
                      marginTop: "2px",
                      opacity: 0.8,
                      fontWeight: 500,
                    }}
                  >
                    effort: {meta.effort}
                  </div>
                )}
              </div>
              {idx < phases.length - 1 && (
                <div
                  style={{
                    flex: "0.5",
                    height: "2px",
                    marginTop: "-20px",
                    background: isComplete ? meta.color : c.border,
                    borderRadius: "1px",
                    transition: "background 0.4s",
                  }}
                />
              )}
            </React.Fragment>
          );
        })}
      </div>
      {currentAction && (
        <div
          className="fade-in"
          style={{
            marginTop: "12px",
            padding: "8px 14px",
            borderRadius: "8px",
            background: `${c.accent}10`,
            border: `1px solid ${c.accent}25`,
            display: "flex",
            alignItems: "center",
            gap: "8px",
            fontSize: "12px",
            color: c.accent,
            fontWeight: 500,
          }}
        >
          <Spinner size={12} />
          {currentAction}
        </div>
      )}
    </div>
  );
}

function ActivityItem({ act, isLast }) {
  const [detailOpen, setDetailOpen] = useState(false);
  const icon = ACTIVITY_ICONS[act.activity_type] || "•";
  const isToolCall = act.activity_type === "tool_call";
  const isToolResult = act.activity_type === "tool_result";
  const isLLM = act.activity_type === "llm_call";
  const isDecision = act.activity_type === "decision";
  const isError = act.activity_type === "error";
  const isPhaseStart = act.activity_type === "phase_start";
  const isPhaseComplete = act.activity_type === "phase_complete";
  const phaseColor = PHASE_META[act.phase]?.color || c.textDim;
  const hasDetail = act.detail && act.detail.length > 0;

  let rowBg = "transparent";
  if (isDecision) rowBg = `${c.accent}08`;
  else if (isError) rowBg = `${c.red}08`;
  else if (isPhaseStart) rowBg = `${phaseColor}06`;

  const time = new Date(act.timestamp).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });

  return (
    <div
      style={{
        display: "flex",
        gap: "10px",
        padding: "7px 10px",
        borderLeft: `2px solid ${
          isPhaseComplete ? phaseColor : isError ? c.red : c.border
        }`,
        marginBottom: isLast ? 0 : "1px",
        background: rowBg,
        borderRadius: "0 6px 6px 0",
        transition: "background 0.2s",
      }}
    >
      <div
        style={{
          width: "22px",
          textAlign: "center",
          fontSize: "12px",
          flexShrink: 0,
          paddingTop: "1px",
        }}
      >
        {icon}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "6px",
            flexWrap: "wrap",
          }}
        >
          <span
            style={{
              fontSize: "12px",
              fontWeight: isDecision || isPhaseStart ? 600 : 500,
              color: isError ? c.red : isDecision ? c.text : c.textDim,
            }}
          >
            {act.title}
          </span>
          <Badge color={phaseColor} small>
            {act.phase}
          </Badge>
          {(isToolCall || isToolResult) && act.metadata?.tool && (
            <Badge
              color={
                isToolResult
                  ? act.metadata.success
                    ? c.green
                    : c.red
                  : c.cyan
              }
              small
            >
              {act.metadata.tool}
            </Badge>
          )}
          {isLLM && act.metadata?.effort && (
            <Badge color={c.pink} small>
              effort: {act.metadata.effort}
            </Badge>
          )}
          {act.metadata?.input_tokens > 0 && (
            <span style={{ fontSize: "10px", color: c.textFaint }}>
              {act.metadata.input_tokens}↓ {act.metadata.output_tokens}↑ tokens
            </span>
          )}
          <span
            style={{
              fontSize: "10px",
              color: c.textFaint,
              marginLeft: "auto",
              flexShrink: 0,
            }}
          >
            {time}
          </span>
        </div>
        {hasDetail && (
          <div style={{ marginTop: "3px" }}>
            <button
              onClick={() => setDetailOpen(!detailOpen)}
              style={{
                fontSize: "10px",
                color: c.accent,
                background: "none",
                fontWeight: 500,
                padding: 0,
              }}
            >
              {detailOpen ? "▾ Hide detail" : "▸ Show detail"}
            </button>
            {detailOpen && (
              <div
                className="fade-in"
                style={{
                  marginTop: "4px",
                  padding: "8px 10px",
                  borderRadius: "6px",
                  background: c.bg,
                  fontSize: "11px",
                  lineHeight: 1.6,
                  color: c.textDim,
                  fontFamily: "'JetBrains Mono', monospace",
                  wordBreak: "break-word",
                  border: `1px solid ${c.border}`,
                  maxHeight: "200px",
                  overflowY: "auto",
                }}
              >
                {act.detail}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function ActivityFeed({ activities, maxItems = 15 }) {
  const [expanded, setExpanded] = useState(false);
  if (!activities || activities.length === 0) return null;
  const displayItems = expanded ? activities : activities.slice(-maxItems);
  const hasMore = activities.length > maxItems && !expanded;
  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: "8px",
        }}
      >
        <div
          style={{
            fontSize: "11px",
            fontWeight: 700,
            color: c.textDim,
            textTransform: "uppercase",
            letterSpacing: "0.5px",
          }}
        >
          Agent Activity ({activities.length})
        </div>
        {hasMore && (
          <button
            onClick={() => setExpanded(true)}
            style={{
              fontSize: "10px",
              color: c.accent,
              background: "none",
              fontWeight: 600,
            }}
          >
            Show all ↓
          </button>
        )}
      </div>
      <div
        style={{
          maxHeight: expanded ? "600px" : "360px",
          overflowY: "auto",
          paddingRight: "4px",
        }}
      >
        {displayItems.map((act, i) => (
          <ActivityItem
            key={i}
            act={act}
            isLast={i === displayItems.length - 1}
          />
        ))}
      </div>
    </div>
  );
}

export default function IncidentDetail({ inc }) {
  return (
    <div
      className="fade-in"
      style={{
        marginTop: "16px",
        paddingTop: "16px",
        borderTop: `1px solid ${c.border}`,
      }}
    >
      <PhaseStepper
        phaseSummary={inc.phase_summary}
        currentAction={inc.current_agent_action}
      />
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "16px",
          marginTop: "16px",
        }}
      >
        <div>
          <div
            style={{
              fontSize: "11px",
              fontWeight: 700,
              color: c.textDim,
              textTransform: "uppercase",
              letterSpacing: "0.5px",
              marginBottom: "10px",
            }}
          >
            Resolution Details
          </div>
          {inc.triage_result && (
            <InfoBlock icon="🔍" title="Triage Result" color={c.orange}>
              {inc.triage_result}
            </InfoBlock>
          )}
          {inc.root_cause && (
            <InfoBlock icon="🎯" title="Root Cause" color={c.cyan}>
              {inc.root_cause}
            </InfoBlock>
          )}
          {inc.fix_applied && (
            <InfoBlock icon="🔧" title="Fix Applied" color={c.green}>
              {inc.fix_applied}
            </InfoBlock>
          )}
          {inc.commit_id && (
            <InfoBlock icon="📝" title="Git Commit" color={c.accent}>
              <span
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: "13px",
                  fontWeight: 700,
                  color: c.accent,
                  background: `${c.accent}15`,
                  padding: "3px 10px",
                  borderRadius: "6px",
                  border: `1px solid ${c.accent}30`,
                  display: "inline-block",
                }}
              >
                {inc.commit_id}
              </span>
            </InfoBlock>
          )}
          <InfoBlock icon="📊" title="Metrics" color={c.textDim}>
            <span>
              Retries: {inc.retry_count || 0} • Cost: $
              {(inc.cost_usd || 0).toFixed(4)} • Activities:{" "}
              {(inc.activity_log || []).length}
            </span>
          </InfoBlock>
          {inc.created_at && (
            <InfoBlock icon="🕐" title="Timeline" color={c.textDim}>
              <div>Created: {new Date(inc.created_at).toLocaleString()}</div>
              {inc.resolved_at && (
                <div>
                  Resolved: {new Date(inc.resolved_at).toLocaleString()}
                </div>
              )}
              {inc.resolved_at && inc.created_at && (
                <div
                  style={{
                    color: c.green,
                    fontWeight: 600,
                    marginTop: "2px",
                  }}
                >
                  Duration:{" "}
                  {formatDuration(
                    new Date(inc.created_at),
                    new Date(inc.resolved_at),
                  )}
                </div>
              )}
            </InfoBlock>
          )}
        </div>
        <div>
          <ActivityFeed activities={inc.activity_log || []} />
        </div>
      </div>
    </div>
  );
}
