/**
 * P3.1-full — App shell.
 *
 * Previously a 1,061-line monolith. Now a ~100-line composition root:
 * it owns the global data hooks (status / incidents / memory / tools /
 * security / config), subscribes to the live SSE incident stream, and
 * hands everything down to the panel components.
 *
 * Push-vs-pull
 * ------------
 * ``useIncidentStream`` opens a long-lived EventSource against the
 * backend's P2.4 broadcaster. On every ``incident.created`` /
 * ``incident.updated`` frame we invalidate both ``/api/status`` and
 * ``/api/incidents`` — no more 5 s polling loop.
 *
 * Memory / tools / security / config still use short polls because
 * those endpoints don't have a push counterpart yet.
 */
import React, { useEffect } from "react";
import { useApi } from "./hooks/useApi";
import { useIncidentStream } from "./hooks/useIncidentStream";

import Layout from "./components/Layout";
import Header from "./components/Header";
import StatusCards from "./components/StatusCards";
import ConfigPanel from "./components/ConfigPanel";
import WatcherControls from "./components/WatcherControls";
import TriggerForm from "./components/TriggerForm";
import SecurityPanel from "./components/SecurityPanel";
import IncidentList from "./components/IncidentList";
import MemoryPanel from "./components/MemoryPanel";
import ToolsPanel from "./components/ToolsPanel";
import { c } from "./theme";

export default function App() {
  const { data: status, refresh: refreshStatus } = useApi("/status", 15000);
  const { data: incidents, refresh: refreshIncidents } = useApi(
    "/incidents",
    15000,
  );
  const { data: memory, refresh: refreshMemory } = useApi("/memory", 30000);
  const { data: tools } = useApi("/tools");
  const { data: security } = useApi("/security", 30000);
  const { data: config } = useApi("/config");

  const { connected: streamConnected, last: streamEvent } = useIncidentStream({
    limit: 50,
  });

  // Any SSE event → re-pull status + incidents so the UI reflects the
  // latest terminal states, tool counts, and cost totals. The polling
  // interval above acts as a slow safety net when the stream is down.
  useEffect(() => {
    if (streamEvent) {
      refreshStatus();
      refreshIncidents();
    }
  }, [streamEvent, refreshStatus, refreshIncidents]);

  const refreshAll = () => {
    refreshStatus();
    refreshIncidents();
    refreshMemory();
  };

  return (
    <Layout>
      <Header
        status={status}
        onRefresh={refreshAll}
        streamConnected={streamConnected}
      />
      <main style={{ maxWidth: "1440px", margin: "0 auto", padding: "20px 28px" }}>
        <StatusCards status={status} />
        <ConfigPanel config={config} />
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: "20px",
          }}
        >
          <WatcherControls
            running={status?.watcher_running}
            onToggle={refreshAll}
          />
          <div style={{ fontSize: "11px", color: c.textFaint }}>
            {streamConnected ? "Live stream connected" : "Stream reconnecting…"}
          </div>
        </div>
        <TriggerForm onTrigger={refreshAll} />
        <SecurityPanel security={security} />
        <IncidentList incidents={incidents} />
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
          <MemoryPanel memory={memory} />
          <ToolsPanel tools={tools} />
        </div>
      </main>
    </Layout>
  );
}
