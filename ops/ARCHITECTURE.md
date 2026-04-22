# Sentry Architecture

Post-P2.4 snapshot. Synchronizes with `implementation_plan.md` and
`HighLevelDesignDoc.md` — this document describes **what is**, not
what will be.

## 1. Request path

```
┌──────────┐        ┌──────────────┐        ┌─────────────────┐
│ Dashboard│ SSE /  │  FastAPI     │        │ ServiceContainer│
│ (React)  │─ HTTP ─▶  create_app  ├────────▶  (DI root)      │
└──────────┘        └──────────────┘        └─────────────────┘
                         │  │  │                     │
                         │  │  │                     ├─ Orchestrator
                         │  │  │                     │   (LangGraph)
                         │  │  └─ RequestIDMiddleware│
                         │  └─ AuthMiddleware        ├─ IncidentBroadcaster
                         └─ CORSMiddleware           │   (P2.4 SSE)
                                                    │
                                                    ├─ ToolExecutor
                                                    │   └─ LocalVault JIT creds
                                                    │   └─ TrustedToolRegistry ACL
                                                    │   └─ SecurityGuard
                                                    │
                                                    ├─ ImmutableAuditLog
                                                    │   (JSON or Postgres)
                                                    ├─ AIGateway
                                                    ├─ AgentThrottle
                                                    ├─ CostCircuitBreaker
                                                    ├─ ISecretsProvider
                                                    │   (env / file / sops / vault)
                                                    └─ IncidentRepository
                                                         (SQLAlchemy async)
```

## 2. Components

### 2.1 Composition root — `backend.shared.factory.build_container`

Single place that instantiates every singleton. Consumed by:

* `backend.api.app.create_app(container=None)` — production path.
* `backend.tests.e2e.conftest.build_live_stack` — test path.

### 2.2 Orchestrator (`backend/orchestrator/engine.py`)

LangGraph state machine driver. Key responsibilities:

1. **Fingerprint dedup** (P1.3) — same `(source|pattern|line)` hash
   inside a 60s window short-circuits to `None`.
2. **Timeout** (P1.3) — wraps `self._graph.ainvoke(state)` in
   `asyncio.wait_for(..., self._orch_timeout)`. TimeoutError →
   ESCALATED.
3. **Persistence** (P1.2) — when `incident_repo` is wired, saves on
   creation and at terminal state.
4. **Broadcast** (P2.4) — publishes `incident.created` +
   `incident.updated` to the shared `IncidentBroadcaster`.
5. **Metrics** (P2.3b) — increments `sentry_incidents_total{state}`
   and `sentry_circuit_breaker_trips_total` as appropriate.

### 2.3 Agents (`backend/agents/`)

| Agent      | Role          | Tools (via registry ACL)                           |
|------------|---------------|-----------------------------------------------------|
| Triage     | classify      | read_file, grep_search, fetch_docs, run_diagnostics |
| Detective  | root-cause    | ⟨same⟩ + memory lookups                             |
| Surgeon    | remediate     | ⟨read-only⟩ + `apply_patch`, `restart_service`      |
| Validator  | verify        | read_file, grep_search, run_diagnostics             |

The Surgeon is the only agent that can call write tools. Every tool
call issues a JIT credential (P1.4) scoped to `tool:<name>` that the
`ToolExecutor` verifies before dispatching.

### 2.4 Tool executor (`backend/tools/executor.py`)

Defense-in-depth gates, evaluated in order:

1. **JIT credential** — must be vault-issued, right scope, not revoked.
2. **Audit entry** — log the attempt before anything else.
3. **Mode** — AUDIT/DISABLED short-circuit write tools.
4. **STOP_SENTRY** — host file → block all write tools.
5. **Registry ACL** — role-based allow-list.
6. **Validation** — Pydantic schema + `SecurityGuard` checks.
7. **Execute** — finally call the tool.

### 2.5 Persistence (P1.2) — `backend/persistence/`

SQLAlchemy 2.0 async. Two modes:

* `DATABASE_URL` empty → JSON memory store + JSONL audit log
  (legacy, dev-friendly).
* `DATABASE_URL` set → `PostgresMemoryRepo` + `PostgresAuditLog` +
  `IncidentRepository`. Alembic migration installs an append-only
  trigger on `audit_log` so UPDATEs/DELETEs are rejected at the DB
  layer (SEC-30).

### 2.6 Auth (P2.1) — `backend/api/auth.py`

* `Principal` frozen dataclass (id, name, role, scopes).
* `TokenRegistry` — `sha256(raw) → Principal` + revocation set.
* `AuthMiddleware` — open paths = `{/api/health, /metrics, /docs,
  /redoc, /openapi.json, /}`. Everything else demands a Bearer token
  unless the registry is empty (dev mode).
* `require_scope(*scopes)` — FastAPI dependency factory enforced on
  each route.

### 2.7 Secrets (P2.2) — `backend/shared/secrets.py`

`ISecretsProvider` ABC with four OSS backends. Selected at startup
via `settings.secrets_backend`. The factory opportunistically
hydrates `api_auth_token` from the provider when the raw env var is
empty, so production deployments can keep their tokens in
Vault / OpenBao / sops without ever touching `.env`.

### 2.8 Observability

* **P2.3a — health/ready split.** `/api/health` (liveness) stays
  shallow; `/api/ready` runs LLM/DB/disk probes.
* **P2.3b — Prometheus /metrics.** Counters live in
  `backend/shared/metrics.py` with a graceful-degradation wrapper so
  dev machines without `prometheus_client` stay green.
* **P2.4 — SSE broadcaster.** `/api/stream/incidents` — hand-rolled
  `text/event-stream` with 15 s keepalive and `event: connected`
  hello frame. Zero third-party dependency.
* **Every response** carries `X-Request-ID` (P1.1).

## 3. Data model

See `backend/shared/models.py` (domain DTOs) and
`backend/persistence/models.py` (SQLAlchemy rows). Key invariants:

* `Incident.state` moves through `TRIAGE → DIAGNOSIS → REMEDIATION →
  VERIFICATION → RESOLVED | IDLE | ESCALATED`. Terminal states are
  removed from `_active_incidents` in a `finally` block — this was
  the single worst pre-P0 bug (ESCALATED leak).
* `AuditLogRow` is append-only via a Postgres trigger + hash chain
  on `prev_hash → entry_hash`.

## 4. Testing model

| Layer        | Dir                              | Count                           |
|--------------|----------------------------------|---------------------------------|
| Unit         | `backend/tests/test_*.py`        | ~630 (dev)                      |
| E2E (gated)  | `backend/tests/e2e/test_*.py`    | ~55 (SENTRY_E2E=1)             |
| Integration  | `backend/tests/integration/*.py` | on Postgres (SENTRY_IT=1, CI)   |
| Frontend     | `frontend/src/**/__tests__`      | vitest (P3.1, partial)          |

Catalog and scoreboard: [`ops/E2E_TEST_CATALOG.md`](./E2E_TEST_CATALOG.md).
Current target: **695 passed / 7 skipped / 1 xfailed / 0 failed** as of
P2.4 + P2.3b + metrics.

## 5. Deployment topology

Single host, docker-compose. Services:

| Service   | Image                              | Exposed          |
|-----------|------------------------------------|------------------|
| backend   | `ghcr.io/<org>/sentry-backend`     | 8000 (internal)  |
| frontend  | `ghcr.io/<org>/sentry-frontend`    | 3000 (nginx)     |
| postgres  | `postgres:16-alpine`               | *not exposed*    |
| prometheus| `prom/prometheus` (optional)       | 9090             |
| grafana   | `grafana/grafana-oss` (optional)   | 3030             |
| openbao   | `openbao/openbao` (optional)       | 8200             |

Multi-replica backend is out of scope: the `IncidentBroadcaster`,
token registry, dedup cache, and audit-log writer are all in-process
singletons. Scaling horizontally would require pushing these to
Redis / NATS / Postgres — a future P4.
