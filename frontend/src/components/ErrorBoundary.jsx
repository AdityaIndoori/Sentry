/**
 * P3.1 — Top-level React error boundary.
 *
 * Wraps the app tree so an unhandled rendering error shows a friendly
 * fallback instead of a blank white screen. The original error is
 * logged to the console so dev tools can pick it up; it's also
 * available via the "Details" toggle.
 *
 * Usage:
 *
 *     import { ErrorBoundary } from "./components/ErrorBoundary";
 *     ReactDOM.createRoot(...).render(
 *       <ErrorBoundary><App /></ErrorBoundary>
 *     );
 */

import React from "react";

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, showDetails: false };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // eslint-disable-next-line no-console
    console.error("[ErrorBoundary]", error, info);
  }

  handleReset = () => {
    this.setState({ error: null, showDetails: false });
    // Full reload is the safest recovery for most dashboard-level
    // failures — React state may be corrupt after a crash.
    if (typeof window !== "undefined") window.location.reload();
  };

  render() {
    const { error, showDetails } = this.state;
    if (!error) return this.props.children;

    const detail =
      error && (error.stack || error.message || String(error))
        ? String(error.stack || error.message || error)
        : "(no details available)";

    return (
      <div
        role="alert"
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#0b0d13",
          color: "#e4e8f1",
          fontFamily:
            "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
          padding: "2rem",
        }}
      >
        <div style={{ maxWidth: 640, width: "100%" }}>
          <h1 style={{ color: "#f87171", marginTop: 0 }}>
            Sentry dashboard crashed
          </h1>
          <p style={{ color: "#8891a8" }}>
            Something went wrong rendering the UI. The backend is unaffected
            — your incidents and audit log are safe.
          </p>
          <button
            type="button"
            onClick={this.handleReset}
            style={{
              padding: "0.5rem 1rem",
              background: "#7c6aef",
              color: "#fff",
              border: "none",
              borderRadius: 4,
              cursor: "pointer",
              marginRight: "0.5rem",
            }}
          >
            Reload
          </button>
          <button
            type="button"
            onClick={() =>
              this.setState((s) => ({ showDetails: !s.showDetails }))
            }
            style={{
              padding: "0.5rem 1rem",
              background: "transparent",
              color: "#8891a8",
              border: "1px solid #232840",
              borderRadius: 4,
              cursor: "pointer",
            }}
          >
            {showDetails ? "Hide" : "Show"} details
          </button>

          {showDetails && (
            <pre
              style={{
                marginTop: "1rem",
                padding: "1rem",
                background: "#141721",
                border: "1px solid #232840",
                borderRadius: 4,
                overflow: "auto",
                maxHeight: 300,
                fontSize: 12,
                whiteSpace: "pre-wrap",
                color: "#f87171",
              }}
            >
              {detail}
            </pre>
          )}
        </div>
      </div>
    );
  }
}

export default ErrorBoundary;
