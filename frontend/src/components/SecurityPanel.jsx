/**
 * P3.1-full — Zero-Trust security panel: layers + agent role matrix.
 */
import React from "react";
import { c } from "../theme";
import { Badge, Card, SectionTitle } from "./ui";

export default function SecurityPanel({ security }) {
  if (!security) return null;
  const modeColor =
    security.mode === "ACTIVE"
      ? c.green
      : security.mode === "AUDIT"
      ? c.orange
      : c.red;

  return (
    <Card style={{ marginBottom: "20px" }}>
      <SectionTitle
        icon="🔐"
        right={
          <div
            style={{ display: "flex", gap: "8px", alignItems: "center" }}
          >
            <Badge color={modeColor}>{security.mode} MODE</Badge>
            {security.stop_file_active && (
              <Badge color={c.red}>⛔ STOP FILE</Badge>
            )}
          </div>
        }
      >
        Zero Trust Security
      </SectionTitle>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(5, 1fr)",
          gap: "8px",
          marginBottom: "16px",
        }}
      >
        {(security.security_layers || []).map((layer, i) => (
          <div
            key={i}
            style={{
              padding: "10px",
              borderRadius: "8px",
              background: c.bg,
              border: `1px solid ${c.border}`,
              textAlign: "center",
              transition: "border-color 0.3s",
            }}
          >
            <div
              style={{
                fontSize: "16px",
                marginBottom: "4px",
                color: c.green,
              }}
            >
              {layer.status}
            </div>
            <div
              style={{
                fontSize: "10px",
                fontWeight: 700,
                color: c.text,
                marginBottom: "2px",
              }}
            >
              {layer.name}
            </div>
            <div
              style={{
                fontSize: "9px",
                color: c.textFaint,
                lineHeight: 1.3,
              }}
            >
              {layer.description}
            </div>
          </div>
        ))}
      </div>
      {security.agent_roles && (
        <div>
          <div
            style={{
              fontSize: "11px",
              fontWeight: 700,
              color: c.textDim,
              textTransform: "uppercase",
              letterSpacing: "0.5px",
              marginBottom: "8px",
            }}
          >
            Agent Role Permissions (Least Privilege)
          </div>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            {Object.entries(security.agent_roles).map(([role, info]) => {
              const roleColors = {
                supervisor: c.pink,
                triage: c.orange,
                detective: c.cyan,
                surgeon: c.accent,
                validator: c.green,
              };
              const roleIcons = {
                supervisor: "👑",
                triage: "🔍",
                detective: "🕵️",
                surgeon: "🔧",
                validator: "✅",
              };
              return (
                <div
                  key={role}
                  style={{
                    padding: "8px 14px",
                    borderRadius: "8px",
                    background: c.bg,
                    border: `1px solid ${c.border}`,
                    flex: "1",
                    minWidth: "150px",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      marginBottom: "4px",
                    }}
                  >
                    <span style={{ fontSize: "14px" }}>
                      {roleIcons[role] || "🤖"}
                    </span>
                    <span
                      style={{
                        fontSize: "11px",
                        fontWeight: 700,
                        color: roleColors[role] || c.text,
                        textTransform: "uppercase",
                      }}
                    >
                      {role}
                    </span>
                    <Badge color={roleColors[role] || c.textDim} small>
                      {info.tool_count} tools
                    </Badge>
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "3px" }}>
                    {(info.tools_allowed || []).map((tool, j) => (
                      <span
                        key={j}
                        style={{
                          fontSize: "9px",
                          padding: "1px 6px",
                          borderRadius: "4px",
                          background: `${roleColors[role] || c.textDim}12`,
                          color: roleColors[role] || c.textDim,
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {tool}
                      </span>
                    ))}
                    {(info.tools_allowed || []).length === 0 && (
                      <span
                        style={{
                          fontSize: "9px",
                          color: c.textFaint,
                          fontStyle: "italic",
                        }}
                      >
                        No tool access (routing only)
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </Card>
  );
}
