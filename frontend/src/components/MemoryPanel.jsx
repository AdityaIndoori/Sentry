/**
 * P3.1-full — Long-term memory panel.
 */
import React from "react";
import { c } from "../theme";
import { Card, SectionTitle } from "./ui";

export default function MemoryPanel({ memory }) {
  if (!memory) return null;
  return (
    <Card>
      <SectionTitle icon="🧠">Long-Term Memory</SectionTitle>
      <div style={{ display: "flex", gap: "24px", marginBottom: "14px" }}>
        <div>
          <div
            style={{ fontSize: "28px", fontWeight: 800, color: c.accent }}
          >
            {memory.count || 0}
          </div>
          <div style={{ fontSize: "11px", color: c.textDim }}>
            Stored Incidents
          </div>
        </div>
        <div>
          <div style={{ fontSize: "11px", color: c.textDim }}>Fingerprint</div>
          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: "11px",
              color: c.textFaint,
              marginTop: "2px",
            }}
          >
            {memory.fingerprint || "Not set"}
          </div>
        </div>
      </div>
      {memory.entries?.length > 0 && (
        <div style={{ maxHeight: "180px", overflowY: "auto" }}>
          {memory.entries.slice(-5).map((e, i) => (
            <div
              key={i}
              style={{
                padding: "8px 12px",
                borderRadius: "7px",
                marginBottom: "5px",
                background: c.bg,
                fontSize: "11px",
                border: `1px solid ${c.border}`,
              }}
            >
              <div style={{ fontWeight: 600, color: c.text }}>{e.id}</div>
              <div style={{ color: c.textDim, marginTop: "2px" }}>
                {e.symptom}
              </div>
              <div style={{ color: c.textFaint, marginTop: "2px" }}>
                Fix: {e.fix} | Tags: {e.vectors?.join(", ")}
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
