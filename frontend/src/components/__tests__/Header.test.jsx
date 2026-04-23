/**
 * P4.3 — Header render + interaction tests.
 */
import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import Header from "../Header";

describe("Header", () => {
  it("shows the Sentry title + subtitle", () => {
    render(<Header status={null} onRefresh={() => {}} />);
    expect(screen.getByText("Sentry")).toBeInTheDocument();
    expect(screen.getByText(/Self-Healing/i)).toBeInTheDocument();
  });

  it("renders the current mode badge", () => {
    render(<Header status={{ mode: "ACTIVE" }} onRefresh={() => {}} />);
    expect(screen.getByText("ACTIVE")).toBeInTheDocument();
  });

  it("shows a live pill when the SSE stream is connected", () => {
    render(
      <Header status={{ mode: "AUDIT" }} streamConnected onRefresh={() => {}} />,
    );
    expect(screen.getByText(/live/i)).toBeInTheDocument();
  });

  it("shows a poll pill when SSE is disconnected", () => {
    render(
      <Header
        status={{ mode: "AUDIT" }}
        streamConnected={false}
        onRefresh={() => {}}
      />,
    );
    expect(screen.getByText(/poll/i)).toBeInTheDocument();
  });

  it("invokes onRefresh when the button is clicked", () => {
    const onRefresh = vi.fn();
    render(<Header status={{ mode: "ACTIVE" }} onRefresh={onRefresh} />);
    fireEvent.click(screen.getByRole("button"));
    expect(onRefresh).toHaveBeenCalledTimes(1);
  });
});
