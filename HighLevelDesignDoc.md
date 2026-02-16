# Design Doc: Claude Sentry (v1.0)

## 1. Executive Summary

Claude Sentry is a "Self-Healing Server Monitor" that uses **Anthropic Claude Opus 4.6 LLM** exclusively to diagnose and fix infrastructure incidents. Unlike traditional monitoring (which alerts humans) or rigid automation (which runs scripts), Sentry uses **Adaptive Thinking** to reason about unique errors and strictly defined **MCP Tools** to execute fixes.

### 1.1 Goals

* **Autonomous Triage:** Reduce "PagerDuty" noise by 90% by resolving routine errors (disk space, service restarts) without human intervention.
* **Context Continuity:** Maintain a long-running "memory" of server health using Opus 4.6’s 1M context window and context compaction.
* **Safety First:** Prevent "hallucinated destructive commands" via strict MCP protocol and read-only default modes.

### 1.2 Non-Goals

* **Real-time Metrics:** Sentry is not a replacement for Datadog/Prometheus. It reacts to *events*, it does not stream charts.
* **Multi-Agent Swarms:** We explicitly avoid "Chatty" agent-to-agent architectures to reduce latency and cost.

### 1.3 Implementation Status

✅ **Fully implemented** with 165 passing tests, Docker microservice deployment, React dashboard, and Zero Trust security. See Section 10 for implementation details.

---

## 2. System Architecture

We utilize a **Controller/Worker** pattern. The reasoning engine (Opus) is decoupled from the execution environment (Sentry Node).

### 2.1 System Context Diagram (C4 Level 1)

This diagram illustrates how Sentry sits between the Administrator and the Server.

```mermaid
graph TD
    User[System Administrator]
    
    subgraph "Claude Sentry System"
        Sentry[Sentry Orchestrator]
    end
    
    subgraph "External Systems"
        Server[Target Server / Cloud]
        Opus[Claude Opus 4.6 API]
        Notify[Slack / PagerDuty]
    end

    Server -- "1. Error Logs / Health Signals" --> Sentry
    Sentry -- "2. Analysis Request" --> Opus
    Opus -- "3. Reasoning & Tool Calls" --> Sentry
    Sentry -- "4. Execute Fix (MCP)" --> Server
    Sentry -- "5. Resolution Report" --> User
    Sentry -- "6. Alert (if Unsolvable)" --> Notify

    style Sentry fill:#f9f,stroke:#333,stroke-width:4px
    style Opus fill:#000,stroke:#fff,color:#fff

```

### 2.2 Container Diagram (C4 Level 2)

The internal modularity of the Sentry Orchestrator.

```mermaid
graph TB
    subgraph "Sentry Node (Python Service)"
        Watcher[Log Watcher Module]
        Orch[Orchestrator Core]
        Memory[Local Memory JSON]
        MCP[MCP Server Tools]
    end

    subgraph "The Brain"
        API[Opus 4.6 API]
    end

    %% Flows
    Watcher -- "Trigger Event" --> Orch
    Orch -- "Read/Write" --> Memory
    Orch -- "HTTP / Stream" --> API
    API -- "Tool Execution Request" --> Orch
    Orch -- "Delegate" --> MCP
    MCP -- "FS / Shell Access" --> Server[(Local OS / Files)]

    %% Styling
    classDef core fill:#d4e1f5,stroke:#000
    class Watcher,Orch,Memory,MCP core
```

---

## 3. Key Design Decisions

### 3.1 Decision: Single Model (Opus 4.6) vs. Multi-Model

* **Alternative:** Use Haiku for triage and Opus for fixing.
* **Decision:** Use **Opus 4.6 exclusively** with `effort` control.
* **Reasoning:** Handing off context between a "dumb" model and a "smart" model results in loss of nuance (the "Chinese Whispers" effect). Opus 4.6 allows us to scale compute up or down *within the same context window*.

### 3.2 Decision: MCP vs. Direct Shell

* **Alternative:** Allow the LLM to output bash blocks (e.g., ```bash rm -rf / ```).
* **Decision:** Use **Model Context Protocol (MCP)**.
* **Reasoning:** Security. MCP forces the model to use specific, pre-coded functions (`read_file`, `restart_service`). We can enforce input validation at the code level, preventing command injection.

---

## 4. Detailed Component Design

### 4.1 The Orchestrator (State Machine)

The Orchestrator is a finite state machine that manages the "Adaptive Effort" loop. It decides how much "brain power" to allocate based on the error severity.

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Triage: Log Error Detected
    
    state Triage {
        [*] --> CallOpusLow
        CallOpusLow --> Analyze: effort="low"
        Analyze --> Ignore: False Positive
        Analyze --> Diagnosis: Critical Issue
    }

    state Diagnosis {
        [*] --> CallOpusHigh
        CallOpusHigh --> DeepThink: effort="high"
        DeepThink --> ToolLoop: Needs Info
        ToolLoop --> DeepThink: Tool Output
        DeepThink --> PlanFix: Root Cause Found
    }

    state Remediation {
        PlanFix --> ApplyFix: effort="medium"
        ApplyFix --> Verify: Run Health Check
        Verify --> Success: Fixed
        Verify --> Diagnosis: Failed (Retry)
        Verify --> Escalate: Failed (Max Retries)
    }

    Ignore --> Idle
    Success --> CompactContext
    Escalate --> NotifyHuman
    CompactContext --> Idle

```

### 4.2 The "Thinking" Configuration

We map incident types to Opus `thinking` parameters.

| Incident Type | Thinking Type | Effort | Purpose |
| --- | --- | --- | --- |
| **Routine** (Disk full, Service stopped) | `adaptive` | `low` | Quick pattern matching. Fast execution. |
| **Unknown** (Stack trace, Latency spike) | `adaptive` | `high` | Deep reasoning. Analyze code logic vs. system state. |
| **Verification** (Post-fix check) | `disabled` | N/A | Simple deterministic check. |

---

## 5. Interface Design (MCP Tools)

The MCP Server exposes the following tools. Each tool is a Python function decorated with `@mcp.tool`.

### 5.1 Read-Only Tools (Safe)

* **`read_file(path: str)`**
* *Constraint:* Must be within `PROJECT_ROOT`. No `../` allowed.


* **`grep_search(query: str, path: str)`**
* *Constraint:* Max 100 results.


* **`fetch_docs(url: str)`**
* *Constraint:* Allow-list domains only (e.g., `docs.python.org`, `stackoverflow.com`). Used to replace the "Researcher Agent."



### 5.2 Active Tools (Requires Permission or SRE Mode)

* **`run_diagnostics(command: str)`**
* *Constraint:* Whitelist only (`ps aux`, `netstat`, `curl`, `tail`).


* **`apply_patch(diff: str, file_path: str)`**
* *Constraint:* Never overwrites. Creates a backup `.bak` file automatically.


* **`restart_service(service_name: str)`**
* *Constraint:* Rate limited (Max 1 restart / 10 mins).



---

## 6. Data Design: Long-Term Memory

To enable "Self-Healing," we use a local JSON store that acts as RAG (Retrieval-Augmented Generation) for the agent.

**File:** `sentry_memory.json`

```json
{
  "system_fingerprint": "Ubuntu-24.04-Nginx-Postgres",
  "incident_history": [
    {
      "id": "INC-2025-10-01",
      "symptom": "502 Bad Gateway on /api/login",
      "root_cause": "Postgres connection pool exhaustion",
      "fix": "Increased max_connections in pool.py from 10 to 50",
      "vectors": ["postgres", "502", "pool"]
    }
  ]
}

```

**Context Compaction Logic:**
Before every new session, the Orchestrator reads this JSON. If `incident_history` > 50 items, Opus 4.6 (Effort: High) is triggered to summarize similar incidents into generalized "Rules of Thumb" to save token space.

---

## 7. Process Flow: Incident Response

This sequence diagram details the interaction between the components during a live bug.

```mermaid
sequenceDiagram
    autonumber
    participant App as Application
    participant Watch as Watcher
    participant Orch as Orchestrator
    participant Opus as Opus 4.6 (API)
    participant MCP as MCP Server

    App->>Watch: Writes "ConnectionRefusedError" to log
    Watch->>Orch: Trigger(Payload)
    
    rect rgb(240, 248, 255)
        note right of Orch: Phase 1: Triage (Low Effort)
        Orch->>Opus: "Analyze this log snippet."
        Opus-->>Orch: "It's a DB connection error. Investigate code."
    end

    rect rgb(255, 240, 245)
        note right of Orch: Phase 2: Diagnosis (High Effort)
        Orch->>Opus: "Find root cause. Here is file tree."
        loop Investigation Loop
            Opus->>MCP: read_file("config/db.py")
            MCP-->>Opus: [File Content]
            Opus->>MCP: run_diagnostics("ping db-host")
            MCP-->>Opus: "Ping successful"
        end
        Opus-->>Orch: "Diagnosis: Credential mismatch in config."
    end

    rect rgb(240, 255, 240)
        note right of Orch: Phase 3: Repair (Medium Effort)
        Orch->>Opus: "Propose fix."
        Opus->>MCP: apply_patch("config/db.py", diff)
        MCP-->>Opus: "Patch Applied"
        Opus->>MCP: restart_service("app_service")
        MCP-->>Opus: "Service Restarted"
    end
    
    Orch->>Watch: Reset Monitor

```

---

## 8. Security & Guardrails

Since this agent has write access to code, we implement "Defense in Depth."

1. **The "Human Switch":** A physical file (`STOP_SENTRY`) or Env Var (`SENTRY_MODE=AUDIT`). If set to `AUDIT`, `apply_patch` and `restart_service` simply log the intent but do not execute.
2. **Diff Validation:** The `apply_patch` tool uses `git apply --check` first to ensure the patch applies cleanly to the current HEAD.
3. **Token Circuit Breaker:** If the agent enters a loop and consumes > $5.00 in 10 minutes, the Orchestrator terminates the process.

### 8.1 Zero Trust Security (Implemented)

The implementation goes far beyond the original 3 guardrails. We implemented a full **Zero Trust Architecture** with 15 security layers:

| # | Layer | Module | Description |
|---|-------|--------|-------------|
| 1 | **NHI Vault** | `vault.py` | Non-Human Identity management — each agent gets a unique cryptographic ID with scoped, TTL-based credentials |
| 2 | **AI Gateway** | `ai_gateway.py` | Prompt injection detection (system prompt override, role hijack, delimiter injection) + PII leak prevention (emails, API keys, passwords, IPs) |
| 3 | **Immutable Audit Log** | `audit_log.py` | Hash-chained (blockchain-style) tamper-evident append-only logging |
| 4 | **Agent Throttle** | `agent_throttle.py` | Per-agent rate limiting with configurable windows |
| 5 | **Tool Registry** | `tool_registry.py` | Role-based tool access control (Least Privilege) |
| 6 | **Human Switch** | `security.py` | `STOP_SENTRY` file or `SENTRY_MODE=AUDIT` halts writes |
| 7 | **Path Validation** | `security.py` | Resolved paths checked against `PROJECT_ROOT`, no `../` |
| 8 | **Command Whitelist** | `security.py` | Only `ps`, `netstat`, `curl`, `tail`, `df`, `free`, `uptime`, `systemctl status`, `ping` |
| 9 | **URL Allow-List** | `security.py` | Only approved domains for `fetch_docs` |
| 10 | **Input Sanitization** | `security.py` | Strips `;`, `\|`, `` ` ``, `$()`, `&&`, `\|\|` |
| 11 | **Rate Limiting** | `circuit_breaker.py` | Max 1 service restart per 10 minutes per service |
| 12 | **Cost Circuit Breaker** | `circuit_breaker.py` | Auto-halt at $5/10min API spend |
| 13 | **Diff Validation** | `patch_tool.py` | `git apply --check` before writing |
| 14 | **Non-Root Docker** | `Dockerfile` | Runs as `sentry` user with `no-new-privileges` |
| 15 | **Security Headers** | `nginx.conf` | CSP, X-Frame-Options, X-Content-Type-Options |

---

## 9. Future Work

* **Slack Integration:** Allow the user to "Chat with Sentry" to ask "Why did you restart the server?"
* **Vector Database:** Migrate `sentry_memory.json` to a local vector store (like ChromaDB) if incident history exceeds 1,000 items.

---

## 10. Implementation Details

This section documents what was actually built vs. the original design.

### 10.1 Technology Stack

| Component | Technology | Notes |
|-----------|-----------|-------|
| **Backend** | Python 3.12 + FastAPI | REST API gateway, async throughout |
| **Frontend** | React 18 + Vite | Single-page dark-mode dashboard |
| **LLM** | Anthropic Claude Opus 4.6 | Via direct API or AWS Bedrock Gateway |
| **Orchestrator** | LangGraph-style state machine | Custom `IncidentGraph` with typed state |
| **Container** | Docker Compose | 2 services: backend (:8000), frontend (:3000) |
| **Testing** | pytest + pytest-asyncio | 165 tests, TDD approach |
| **Reverse Proxy** | nginx | Frontend serves static + proxies `/api` |

### 10.2 Multi-Agent Architecture

The implementation evolved from the original single-orchestrator design to a **multi-agent pipeline** inspired by OWASP Non-Human Identity (NHI) guidelines:

```
Supervisor (routing only, no LLM)
    ├── Triage Agent     → effort:low,  read-only tools
    ├── Detective Agent  → effort:high, read + diagnostics
    ├── Surgeon Agent    → effort:med,  active tools only
    └── Validator Agent  → effort:off,  diagnostics only
```

Each agent has:
- A **unique Non-Human Identity** (NHI) from the Vault
- **Scoped, time-limited credentials** (TTL-based)
- Access to **only the tools required** for its role (Least Privilege)
- All actions logged to an **immutable audit trail**

#### Tool Access Matrix

| Tool | Supervisor | Triage | Detective | Surgeon | Validator |
|------|:---:|:---:|:---:|:---:|:---:|
| `read_file` | ✅ | ✅ | ✅ | ❌ | ✅ |
| `grep_search` | ✅ | ✅ | ✅ | ❌ | ✅ |
| `fetch_docs` | ✅ | ✅ | ✅ | ❌ | ❌ |
| `run_diagnostics` | ✅ | ❌ | ✅ | ❌ | ✅ |
| `apply_patch` | ✅ | ❌ | ❌ | ✅ | ❌ |
| `restart_service` | ✅ | ❌ | ❌ | ✅ | ❌ |

### 10.3 LLM Provider Abstraction

Supports two backends via a factory pattern (`create_llm_client()`):

1. **Direct Anthropic API** (`OpusLLMClient`) — Uses `anthropic` SDK with extended thinking
2. **AWS Bedrock Access Gateway** (`BedrockGatewayLLMClient`) — OpenAI-compatible proxy for Bedrock-hosted Claude

Both implement the `ILLMClient` interface (SOLID — Dependency Inversion).

### 10.4 SOLID Principles Applied

| Principle | Implementation |
|-----------|---------------|
| **Single Responsibility** | Each agent has exactly one job; each MCP tool is one function |
| **Open/Closed** | Tool registry extensible without modifying agents; new LLM providers via factory |
| **Liskov Substitution** | All agents implement `BaseAgent`; both LLM clients implement `ILLMClient` |
| **Interface Segregation** | Separate `ILLMClient`, `IMemoryStore`, `IToolExecutor` interfaces |
| **Dependency Inversion** | Agents depend on abstractions (`IVault`), not concrete `LocalVault` |

### 10.5 Test Coverage

**165 tests across 9 test files:**

| Test File | Tests | Coverage Area |
|-----------|-------|---------------|
| `test_zero_trust.py` | 43 | NHI Vault, AI Gateway, Audit Log, Throttle, Tool Registry |
| `test_agents.py` | 24 | Agent identity, tool isolation, routing, gateway integration |
| `test_security.py` | 20 | Path validation, command whitelist, URL allow-list, input sanitization |
| `test_tools.py` | 14 | MCP tool execution, path traversal blocking, audit mode |
| `test_llm_client.py` | 18 | Effort budgets, Opus client, Bedrock Gateway, factory |
| `test_memory.py` | 10 | JSON store CRUD, fingerprint, keyword search |
| `test_schemas.py` | 14 | LLM output parsing, validation |
| `test_circuit_breaker.py` | 10 | Cost tracking, rate limiting, auto-halt |
| `test_api.py` | 12 | Health, status, incidents, trigger, watcher endpoints |

### 10.6 Docker Deployment

```yaml
# Two-container microservice architecture
services:
  backend:   # FastAPI on :8000, non-root, healthcheck
  frontend:  # React (nginx) on :3000, security headers, /api proxy
```

Both containers run with `security_opt: no-new-privileges:true`.

### 10.7 Dashboard Features

The React frontend provides:
- **System Status Cards** — Active incidents, resolved count, API cost, circuit breaker
- **Log Watcher Controls** — Start/stop file monitoring
- **Manual Trigger** — Paste error messages for on-demand analysis
- **Zero Trust Security Panel** — 10 security layer status indicators
- **Agent Role Permissions** — Visual tool access matrix per agent
- **Incident Timeline** — Active/resolved tabs with detailed activity logs
- **Long-Term Memory** — Incident history with keyword vectors
- **MCP Tools Reference** — Read-only and active tool documentation
