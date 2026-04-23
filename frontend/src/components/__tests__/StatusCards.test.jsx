/**
 * P3.1-full — StatusCards render tests.
 */
import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import StatusCards from "../StatusCards";

describe("StatusCards", () => {
  it("renders nothing when status is null", () => {
    const { container } = render(<StatusCards status={null} />);
    expect(container.firstChild).toBeNull();
  });

  it("shows the active incidents count", () => {
    render(
      <StatusCards
        status={{
          active_incidents: 3,
          resolved_total: 7,
          circuit_breaker: { current_cost_usd: 0.42, max_cost_usd: 5, tripped: false },
        }}
      />,
    );
    expect(screen.getByText("Active Incidents")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText(/\$0\.4200/)).toBeInTheDocument();
    expect(screen.getByText("OK")).toBeInTheDocument();
  });

  it("flags a tripped circuit breaker", () => {
    render(
      <StatusCards
        status={{
          active_incidents: 0,
          resolved_total: 0,
          circuit_breaker: { current_cost_usd: 9.99, max_cost_usd: 5, tripped: true },
        }}
      />,
    );
    expect(screen.getByText("TRIPPED")).toBeInTheDocument();
  });
});
