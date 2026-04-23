/**
 * P3.1-full — Design tokens.
 *
 * Extracted from the monolithic App.jsx; every component now imports
 * ``{ c, PHASE_META, ACTIVITY_ICONS }`` from here so palette changes
 * touch a single file.
 */

export const c = {
  bg: "#0b0d13",
  surface: "#141721",
  surfaceAlt: "#1a1e2e",
  border: "#232840",
  borderLight: "#2e3452",
  text: "#e4e8f1",
  textDim: "#8891a8",
  textFaint: "#5c637a",
  accent: "#7c6aef",
  accentDim: "#6c5ce722",
  green: "#34d399",
  greenDim: "#34d39920",
  red: "#f87171",
  redDim: "#f8717120",
  orange: "#fbbf24",
  orangeDim: "#fbbf2420",
  cyan: "#22d3ee",
  cyanDim: "#22d3ee20",
  pink: "#f472b6",
  pinkDim: "#f472b620",
};

export const PHASE_META = {
  triage: { icon: "🔍", label: "Triage", color: c.orange, effort: "Low" },
  diagnosis: { icon: "🧠", label: "Diagnosis", color: c.cyan, effort: "High" },
  remediation: { icon: "🔧", label: "Remediation", color: c.accent, effort: "Medium" },
  verification: { icon: "✅", label: "Verification", color: c.green, effort: "Disabled" },
};

export const ACTIVITY_ICONS = {
  phase_start: "▶",
  phase_complete: "✓",
  llm_call: "🤖",
  tool_call: "⚙",
  tool_result: "📋",
  decision: "💡",
  error: "❌",
  info: "ℹ",
};
