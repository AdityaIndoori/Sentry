/**
 * P4.3 — ToolsPanel render tests.
 */
import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import ToolsPanel from "../ToolsPanel";

describe("ToolsPanel", () => {
  it("renders nothing when tools.tools is missing", () => {
    const { container } = render(<ToolsPanel tools={null} />);
    expect(container.firstChild).toBeNull();
  });

  it("groups read-only vs active tools", () => {
    render(
      <ToolsPanel
        tools={{
          tools: [
            { name: "read_file", description: "Read a file" },
            { name: "grep_search", description: "Search files" },
            { name: "apply_patch", description: "Apply a patch" },
            { name: "restart_service", description: "Restart" },
          ],
        }}
      />,
    );
    expect(screen.getByText("Read-Only (Safe)")).toBeInTheDocument();
    expect(screen.getByText(/Active \(Requires Permission\)/)).toBeInTheDocument();
    expect(screen.getByText("read_file")).toBeInTheDocument();
    expect(screen.getByText("grep_search")).toBeInTheDocument();
    expect(screen.getByText("apply_patch")).toBeInTheDocument();
    expect(screen.getByText("restart_service")).toBeInTheDocument();
  });

  it("omits a group header when it has no items", () => {
    render(
      <ToolsPanel
        tools={{ tools: [{ name: "read_file", description: "d" }] }}
      />,
    );
    expect(screen.getByText("Read-Only (Safe)")).toBeInTheDocument();
    expect(screen.queryByText(/Active \(Requires/)).toBeNull();
  });
});
