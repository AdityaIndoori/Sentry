/**
 * P4.3 — MemoryPanel render tests.
 */
import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import MemoryPanel from "../MemoryPanel";

describe("MemoryPanel", () => {
  it("renders nothing when memory is null", () => {
    const { container } = render(<MemoryPanel memory={null} />);
    expect(container.firstChild).toBeNull();
  });

  it("shows stored count + fingerprint", () => {
    render(
      <MemoryPanel
        memory={{ count: 12, fingerprint: "abc123...", entries: [] }}
      />,
    );
    expect(screen.getByText("Long-Term Memory")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
    expect(screen.getByText("abc123...")).toBeInTheDocument();
  });

  it("falls back to 'Not set' when fingerprint is empty", () => {
    render(<MemoryPanel memory={{ count: 0, fingerprint: "", entries: [] }} />);
    expect(screen.getByText("Not set")).toBeInTheDocument();
  });

  it("shows the last 5 entries with id + symptom", () => {
    const entries = Array.from({ length: 7 }, (_, i) => ({
      id: `INC-${i}`,
      symptom: `symptom ${i}`,
      fix: `fix ${i}`,
      vectors: ["vector"],
    }));
    render(
      <MemoryPanel
        memory={{ count: entries.length, fingerprint: "fp", entries }}
      />,
    );
    // Last 5 → INC-2..INC-6.
    expect(screen.getByText("INC-2")).toBeInTheDocument();
    expect(screen.getByText("INC-6")).toBeInTheDocument();
    // First two should be sliced off.
    expect(screen.queryByText("INC-0")).toBeNull();
    expect(screen.queryByText("INC-1")).toBeNull();
  });
});
