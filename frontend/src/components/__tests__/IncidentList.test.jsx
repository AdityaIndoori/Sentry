/**
 * P3.1-full — IncidentList render tests.
 */
import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import IncidentList from "../IncidentList";

const sampleIncident = (overrides = {}) => ({
  id: "INC-20260422-112233-abcdef",
  symptom: "ConnectionRefusedError: Connection refused",
  state: "resolved",
  severity: "high",
  cost_usd: 0.0321,
  created_at: "2026-04-22T11:22:33Z",
  resolved_at: "2026-04-22T11:24:00Z",
  activity_log: [
    { activity_type: "tool_call", phase: "diagnosis", title: "read_file", timestamp: "2026-04-22T11:23:00Z", metadata: { tool: "read_file" } },
    { activity_type: "llm_call", phase: "triage", title: "Call LLM", timestamp: "2026-04-22T11:22:40Z", metadata: { effort: "Low" } },
  ],
  ...overrides,
});

describe("IncidentList", () => {
  it("shows an empty-state when there are no incidents", () => {
    render(<IncidentList incidents={{ active: [], resolved: [] }} />);
    expect(
      screen.getByText(/No active incidents/i),
    ).toBeInTheDocument();
  });

  it("lists active incidents and updates tab labels", () => {
    const incidents = {
      active: [sampleIncident({ id: "A", state: "triage" })],
      resolved: [
        sampleIncident({ id: "R1" }),
        sampleIncident({ id: "R2" }),
      ],
    };
    render(<IncidentList incidents={incidents} />);
    expect(screen.getByText("Active (1)")).toBeInTheDocument();
    expect(screen.getByText("Resolved (2)")).toBeInTheDocument();
    // The id and uppercase state badge should be visible for the active card
    expect(screen.getByText("A")).toBeInTheDocument();
    expect(screen.getByText("TRIAGE")).toBeInTheDocument();
  });

  it("switches to the resolved tab on click", () => {
    const incidents = {
      active: [],
      resolved: [sampleIncident({ id: "R1" })],
    };
    render(<IncidentList incidents={incidents} />);
    fireEvent.click(screen.getByText("Resolved (1)"));
    expect(screen.getByText("R1")).toBeInTheDocument();
    expect(screen.getByText("RESOLVED")).toBeInTheDocument();
  });
});
