/**
 * P3.1-full — Tools panel: read-only + active tool catalogue.
 */
import React from "react";
import { c } from "../theme";
import { Card, SectionTitle } from "./ui";

const READ_ONLY = new Set(["read_file", "grep_search", "fetch_docs"]);

export default function ToolsPanel({ tools }) {
  if (!tools?.tools) return null;
  const readonly = tools.tools.filter((t) => READ_ONLY.has(t.name));
  const active = tools.tools.filter((t) => !READ_ONLY.has(t.name));

  return (
    <Card>
      <SectionTitle icon="🔧">Tools</SectionTitle>
      {[
        { label: "Read-Only (Safe)", items: readonly, color: c.green },
        {
          label: "Active (Requires Permission)",
          items: active,
          color: c.orange,
        },
      ].map((group) =>
        group.items.length > 0 ? (
          <div key={group.label} style={{ marginBottom: "12px" }}>
            <div
              style={{
                fontSize: "10px",
                fontWeight: 700,
                color: group.color,
                textTransform: "uppercase",
                letterSpacing: "0.5px",
                marginBottom: "6px",
              }}
            >
              {group.label}
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
              {group.items.map((t, i) => (
                <div
                  key={i}
                  style={{
                    padding: "6px 12px",
                    borderRadius: "7px",
                    background: c.bg,
                    border: `1px solid ${c.border}`,
                  }}
                >
                  <div
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: "11px",
                      fontWeight: 600,
                      color: c.text,
                    }}
                  >
                    {t.name}
                  </div>
                  <div
                    style={{
                      fontSize: "10px",
                      color: c.textFaint,
                      marginTop: "1px",
                    }}
                  >
                    {t.description}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : null,
      )}
    </Card>
  );
}
