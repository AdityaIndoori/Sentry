/**
 * P3.1-full — App shell: global styles, main container, footer.
 */
import React from "react";
import { c } from "../theme";
import { GlobalStyles } from "./ui";

export default function Layout({ children }) {
  return (
    <div style={{ background: c.bg, color: c.text, minHeight: "100vh" }}>
      <GlobalStyles />
      {children}
      <footer
        style={{
          textAlign: "center",
          padding: "20px",
          color: c.textFaint,
          fontSize: "11px",
          borderTop: `1px solid ${c.border}`,
          marginTop: "40px",
        }}
      >
        Sentry v1.0 — Self-Healing Server Monitor — Zero Trust Security
      </footer>
    </div>
  );
}
