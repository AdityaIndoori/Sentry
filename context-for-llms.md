# Context for LLMs: Sentry — Self-Healing Server Monitor

This document provides a comprehensive overview of the Sentry project, designed to give an LLM all the necessary context to understand, review, and contribute to the codebase without needing to read every individual file.

## 1. Project Overview
Sentry is an autonomous AI service monitor that uses a multi-agent pipeline to continuously monitor logs, diagnose errors, and fix them automatically. It is built with a focus on **Adaptive Thinking** (using Claude's reasoning capabilities) and **Zero Trust Security**.

### Key Goals:
- **Autonomous Triage:** Automatically resolve routine errors.
- **Context Continuity:** Maintain a long-term memory of incidents.
- **Safety First:** Enforce strict tool usage via MCP and defense-in-depth security.

## 2. Core Architecture
Sentry follows a **Controller/Worker** pattern using a **LangGraph-style state machine** for orchestration.

### 2.1 Multi-Agent Pipeline
The system uses a hierarchy of agents, each with a specific role and least-privilege tool access:
- **Supervisor:** Orchestrates the flow and handles routing (deterministic/minimal LLM).
- **Triage Agent:** Classifies severity and decides whether to investigate (Low effort, Read-only).
- **Detective Agent:** Performs root-cause analysis using diagnostic tools (High effort, Read + Diagnostics).
- **Surgeon Agent:** Proposes and applies fixes (Medium effort, Active tools only).
- **Validator Agent:** Confirms the fix worked (Disabled thinking, Diagnostics only).

### 2.2 Service Awareness Layer
Sentry understands the services it monitors by reading their source code and configuration. It uses `.env` paths (`SERVICE_HOST_PATH`, `WATCH_PATHS`) to build a service registry at runtime.

### 2.3 Long-Term Memory
Incidents are stored in a JSON-based memory store (`sentry_memory.json`). This acts as RAG context for agents to recognize recurring patterns and apply past successful fixes.

## 3. Zero Trust Security (15 Layers)
Every agent is treated as a potentially compromised actor. Security is enforced at multiple layers:
- **NHI Vault:** Unique Non-Human Identities with scoped, TTL-based credentials.
- **AI Gateway:** Filters prompts for injection and outputs for PII leaks.
- **Immutable Audit Log:** Hash-chained, tamper-evident record of every action.
- **Agent Throttle:** Rate-limits agent actions.
- **Tool Registry:** Role-based access control for MCP tools.
- **Circuit Breaker:** Auto-halts if API costs or restart frequencies exceed thresholds.
- **Input Sanitization:** Strict validation of file paths, commands, and URLs.

## 4. MCP Tools (Model Context Protocol)
Agents interact with the system only through predefined tools:
- **Read-Only:** `read_file`, `grep_search`, `fetch_docs`.
- **Diagnostic:** `run_diagnostics` (whitelisted commands: `ps`, `netstat`, `curl`, `tail`, `df`, `free`, `uptime`, `systemctl status`, `ping`).
- **Active:** `apply_patch` (uses `git apply --check`), `restart_service` (rate-limited).

## 5. Technology Stack
- **Backend:** Python 3.12, FastAPI, LangGraph (custom state machine), Anthropic SDK.
- **Frontend:** React 18, Vite, Nginx (as reverse proxy).
- **LLM:** Configurable via `.env` (`LLM_PROVIDER`: `anthropic` or `bedrock_gateway`).
- **Deployment:** Docker Compose (Microservices).
- **Testing:** Pytest (165+ tests covering security, agents, tools, etc.).

## 6. Project Structure
```text
├── backend/
│   ├── agents/           # Agent implementations (BaseAgent, Triage, etc.)
│   ├── api/              # FastAPI endpoints
│   ├── mcp_tools/        # Tool implementations and executor
│   ├── memory/           # JSON-based incident memory
│   ├── orchestrator/     # State machine and LLM client
│   ├── services/         # Service awareness and registry
│   ├── shared/           # Security, vault, audit log, config, models
│   └── tests/            # Comprehensive test suite
├── frontend/
│   ├── src/              # React dashboard
│   └── nginx.conf        # Proxy configuration
├── docs/                 # Screenshots and documentation
├── .env.example          # Configuration template
├── HighLevelDesignDoc.md # Detailed architectural design
└── README.md             # Project landing page
```

## 7. Operating Modes
- **ACTIVE:** Full autonomous remediation.
- **AUDIT:** Read-only analysis (default). Logs intent but does not execute active tools.
- **DISABLED:** All actions blocked.

## 8. Development Guidelines
- **TDD:** Prioritize writing tests for new features (especially security and tools).
- **SOLID:** Follow SOLID principles; use abstractions for LLM clients and stores.
- **Security:** Always validate paths and inputs. Never allow direct shell access.
- **Logging:** Ensure all agent actions are logged via the `AuditLog`.

This summary should provide a solid foundation for reviewing or extending Sentry. For deep dives, refer to `HighLevelDesignDoc.md` and the `backend/shared/` directory for security implementations.
