# Implementation Plan

[Overview]
Fix all correctness bugs, remove dead code, and promote Sentry from a demo-grade repo to a production-grade service with real authentication, persistence, secrets management, observability, and CI/CD — keeping Docker Compose as the primary deployment target.

This plan is organized in four sequenced phases:

- **P0 — Correctness & Dead-Code Removal.** Fix the bugs that matter today: incident leak on ESCALATED, FastAPI global state races, non-atomic memory writes, log-watcher encoding/rotation edge cases, Dockerfile privilege escalation, open API endpoints, and verify that each documented security control is actually on the hot path. Delete `backend/agents/supervisor.py` which is entirely unreferenced.
- **P1 — Production Hardening.** Introduce a DI container replacing FastAPI globals; move from JSON memory store to Postgres (incidents, memory, audit-log); wrap all subprocess/LLM calls with timeouts; add proper concurrency locks and deduplication; split `/api/health` vs `/api/ready`; tighten Zero-Trust claims (either truly enforce JIT credentials at tool boundaries, or honestly scope the README).
- **P2 — Auth, Secrets, Observability.** Bearer-token API auth backed by a pluggable **open-source secrets provider** (HashiCorp Vault OSS / OpenBao is the recommended production backend; sops+age encrypted files for air-gapped / single-node deployments; `.env` file for dev). No proprietary cloud services. OpenTelemetry traces + Prometheus `/metrics`; structured JSON logs with trace correlation; Grafana + Prometheus as sidecar containers; an operations runbook.
- **P3 — CI/CD & Frontend Polish.** GitHub Actions pipeline (lint, type-check, test, image scan, push); split `frontend/src/App.jsx` into components; add an `ErrorBoundary`; switch the dashboard from polling to SSE; tighten nginx CSP.

Why this fits: the codebase is already well-structured around interfaces (`ILLMClient`, `IMemoryStore`, `IToolExecutor`, `IVault`) and a LangGraph state machine (`backend/orchestrator/graph.py`). The biggest production gaps are not architectural — they are real bugs, the absence of authn/persistence/observability, and container privilege issues. Respecting the existing interfaces keeps the change surface small and preserves the 442-test suite.

[Types]
Introduce database-backed domain repositories, an auth/principal type, a settings model, and observability context; keep Pydantic/dataclasses idiomatic and backward-compatible with existing `backend/shared/models.py`.

New/changed type definitions:

1. `backend/shared/principal.py` (new)
   - `@dataclass(frozen=True) class Principal`
     - `id: str` — stable token identifier (e.g., `sk_*` sha256 fingerprint, not the token itself)
     - `name: str`
     - `role: Literal["admin", "operator", "read_only"]`
     - `scopes: frozenset[str]` — e.g. `{"incidents:read", "incidents:trigger", "watcher:control", "config:read"}`
     - `issued_at: datetime`
   - Used by `fastapi.Depends()` in every endpoint.

2. `backend/shared/settings.py` (new — replaces ad-hoc `load_config()`)
   - `class Settings(BaseSettings)` — Pydantic-settings v2. Wraps existing `AppConfig` groups.
     - Adds: `database_url: PostgresDsn`, `secrets_backend: Literal["env","file","sops","vault"]` (all open-source), `secrets_vault_addr: str | None`, `secrets_vault_role: str | None`, `secrets_sops_file: str | None`, `api_auth_token_secret_name: str`, `otel_exporter_otlp_endpoint: str | None`, `prometheus_enabled: bool = True`, `service_name: str = "sentry"`.
     - **Required-at-startup validation** for: `ANTHROPIC_API_KEY` or Bedrock equivalents, `DATABASE_URL`, `API_AUTH_TOKEN` (or secret name), `SERVICE_HOST_PATH`.
     - Fails fast with a readable message listing every missing var, instead of running with empty string defaults the way `config.py` does today.

3. `backend/persistence/models.py` (new, SQLAlchemy 2.0 ORM)
   - `class IncidentRow(Base)` — mirrors `backend.shared.models.Incident` with `id PK`, `state` (enum), `severity`, `symptom`, `root_cause`, `fix_applied`, `retry_count`, `commit_id`, `created_at`, `resolved_at`, `activity_log JSONB`, `log_events JSONB`, `fingerprint_hash TEXT` (for dedup).
   - `class MemoryEntryRow(Base)` — mirrors `MemoryEntry`; `vectors TEXT[]`, `embedding VECTOR(1536)` (optional pgvector column; nullable for now).
   - `class AuditLogRow(Base)` — one row per audit entry; `prev_hash`, `entry_hash`, `agent_id`, `action`, `detail`, `result`, `metadata JSONB`, immutable (no `updated_at`, trigger denies UPDATE/DELETE).
   - `class ApiTokenRow(Base)` — `id`, `token_hash`, `name`, `role`, `scopes`, `revoked_at`, `created_at`.
   - All tables have `CREATE INDEX` on the primary lookup columns and `created_at`.

4. `backend/shared/observability.py` (new)
   - `class Telemetry` — thin holder for the active OpenTelemetry `Tracer` and Prometheus counters/histograms used across the codebase:
     - `incidents_total{state}`, `tool_calls_total{tool,success}`, `llm_tokens_total{direction}`, `llm_cost_usd_total`, `incident_duration_seconds`, `watcher_events_total`, `circuit_breaker_trips_total`, `api_requests_total{method,route,code}`, `api_request_duration_seconds`.

5. `backend/shared/container.py` (new)
   - `@dataclass class ServiceContainer` holding: `config`, `llm`, `tools`, `memory_store`, `incident_repo`, `audit_log`, `vault`, `gateway`, `throttle`, `registry`, `circuit_breaker`, `watcher`, `orchestrator`, `telemetry`.
   - Built once in `lifespan()` and attached to `app.state.container`. All endpoints receive it via `Depends(get_container)`.

6. `backend/shared/models.py` — modify `Incident`:
   - Add `fingerprint: Optional[str]` computed as `hashlib.sha256((source_file + "|" + matched_pattern + "|" + normalized_line).encode()).hexdigest()` — used for 60-second dedup window.

[Files]
New files, modifications, deletions, and config changes listed by relative path.

**New files**

- `backend/shared/principal.py` — `Principal` type + `get_principal()` dependency (validates bearer token, loads scopes).
- `backend/shared/settings.py` — Pydantic-settings based startup validation. Replaces the loose `load_config()` while re-exporting `AppConfig` for test compatibility.
- `backend/shared/container.py` — `ServiceContainer` + `get_container()` FastAPI dependency.
- `backend/shared/observability.py` — OpenTelemetry + Prometheus wiring; `init_telemetry(settings)`; `Telemetry` holder.
- `backend/shared/secrets.py` — Abstract `ISecretsProvider` with four open-source implementations: `EnvSecrets` (reads process env — dev fallback), `FileSecrets` (reads 0600-mode secret files from a mounted tmpfs / docker-compose `secrets:` block), `SopsSecrets` (decrypts a sops-age encrypted YAML via the `sops` CLI), and `VaultSecrets` (HashiCorp Vault OSS / OpenBao via `hvac`; supports both token and AppRole auth). Selected via `settings.secrets_backend`.
- `backend/shared/logging_config.py` — structlog JSON configuration, trace-id / request-id injection.
- `backend/api/auth.py` — token verification, `require_scope()` decorator factory.
- `backend/api/middleware.py` — Extract `RequestIDMiddleware` + add `TimingMiddleware` + `AuthMiddleware` (short-circuits before endpoints for unauthenticated requests).
- `backend/api/dependencies.py` — `get_container`, `get_principal`, `require_scope` wiring for FastAPI `Depends()`.
- `backend/persistence/__init__.py`
- `backend/persistence/models.py` — SQLAlchemy ORM (above).
- `backend/persistence/session.py` — async engine + session factory using `asyncpg`.
- `backend/persistence/repositories/incident_repo.py` — `IncidentRepository` implementing persistence for active/resolved incidents; provides `save`, `get`, `list_active`, `list_resolved`, `mark_resolved`, `mark_escalated`, `dedupe_fingerprint`.
- `backend/persistence/repositories/memory_repo.py` — implements `IMemoryStore` against Postgres.
- `backend/persistence/repositories/audit_repo.py` — implements `ImmutableAuditLog` against Postgres (chain + append-only trigger).
- `backend/persistence/migrations/` — Alembic directory with initial migration creating all tables + triggers.
- `backend/persistence/alembic.ini`
- `backend/api/v1/__init__.py`, `backend/api/v1/routers/` — split existing `app.py` routes into:
  - `health.py` (`/api/health`, `/api/ready`)
  - `incidents.py` (`/api/incidents`, `/api/incidents/{id}`)
  - `trigger.py` (`/api/trigger`)
  - `memory.py` (`/api/memory`)
  - `tools.py` (`/api/tools`)
  - `watcher.py` (`/api/watcher/start`, `/api/watcher/stop`)
  - `config.py` (`/api/config`)
  - `security.py` (`/api/security`)
  - `stream.py` (new: `/api/stream/incidents` SSE for the dashboard)
  - `metrics.py` (new: `/metrics` via `prometheus_client`)
- `backend/frontend_contract/openapi_snapshot.json` — snapshot test artifact so frontend consumers get a stable contract.
- `frontend/src/components/` — new directory with:
  - `StatusCards.jsx`, `IncidentList.jsx`, `IncidentDetail.jsx`, `SecurityPanel.jsx`, `MemoryPanel.jsx`, `ToolsPanel.jsx`, `TriggerForm.jsx`, `WatcherControls.jsx`, `ErrorBoundary.jsx`.
- `frontend/src/api/client.js` — single fetch wrapper reading the bearer token from env var at build-time (or prompt at first load for dev).
- `frontend/src/hooks/useIncidentStream.js` — SSE hook replacing 5-second polling.
- `prometheus/prometheus.yml` — scrape config for the backend `/metrics` endpoint.
- `grafana/provisioning/datasources/prometheus.yml` + `grafana/provisioning/dashboards/sentry.json` — pre-provisioned dashboard.
- `docker/otel-collector-config.yaml` — OTel collector receiving OTLP from backend and exporting to Grafana Tempo/Loki (commented-out; default keeps traces local).
- `ops/RUNBOOK.md` — operator runbook: rotating API keys, killing runaway incidents, resetting circuit breaker, inspecting audit log, enabling `STOP_SENTRY`, rolling back fixes via git.
- `ops/SECURITY.md` — honest threat model and current mitigation status (replaces the inflated claims in README).
- `.github/workflows/ci.yml` — lint (ruff), type-check (mypy), pytest w/ coverage, Trivy image scan, npm build, upload SBOM.
- `.github/workflows/release.yml` — tag-driven push to GHCR.
- `.github/dependabot.yml` — weekly Python + npm + Docker updates.
- `pyproject.toml` — centralizes ruff, mypy, black, pytest configuration; replaces `pytest.ini` and `.coveragerc` (kept as thin shims until tests migrate).
- `backend/tests/integration/test_api_auth.py`
- `backend/tests/integration/test_orchestrator_persistence.py`
- `backend/tests/integration/test_watcher_rotation.py`
- `backend/tests/integration/test_end_to_end.py`
- `backend/tests/integration/test_escalated_cleanup.py`

**Modified files**

- `backend/api/app.py` — slim down: `create_app()` factory, attaches container to `app.state`, wires all routers, installs middleware stack. Remove every module-level `_orchestrator`, `_watcher`, `_config` global. All endpoint handlers currently inlined here will move to the `v1/routers/*.py` files.
- `backend/orchestrator/engine.py`
  - Line 116–122 / 129–131: fix ESCALATED incident leak by unconditionally removing from `_active_incidents` in `finally` and recording terminal state. Back `_resolved_incidents` with `collections.deque(maxlen=MAX_RESOLVED_INCIDENTS)` and persist to `IncidentRepository`. Persist every state transition (so the API can show in-flight incidents across restarts).
  - `handle_event()` gains a cheap **fingerprint dedup** pass: `IncidentRepository.dedupe_fingerprint(fp, window_seconds=60)`; duplicates return early.
  - Wrap `self._graph.ainvoke(initial_state)` with `asyncio.wait_for(..., timeout=settings.orchestrator_timeout_seconds)`; on `TimeoutError`, mark ESCALATED and record metric.
  - Emit OTel spans per phase and Prometheus counters per state.
- `backend/orchestrator/graph.py`
  - Remove inline agent instantiation per node (lines ~151, 231, 292, 353) — accept an `AgentFactory` in the builder instead, so NHIs are registered once and JIT credentials are actually used. Pass `credential` into `_call_llm` / `_call_tool` and have those require the credential on the `ToolExecutor`.
  - Add timeout via `asyncio.wait_for` around every `agent.run(...)` call.
  - Line 449–491 `_auto_commit_fix`: add `pragma: no cover` check can stay; but gate on `settings.auto_commit_enabled` and record the commit hash to the `IncidentRow`.
- `backend/agents/base_agent.py`
  - `_call_llm()` and `_call_tool()` request a `JITCredential` for scope `llm_call` and scope `tool:<name>` respectively, pass the credential to downstream, and revoke it on exit. This makes the vault actually enforcing rather than ornamental.
  - Add `async def close(self)` that revokes any outstanding credentials on the agent's NHI.
- `backend/shared/vault.py`
  - `verify_credential()` becomes mandatory in `ToolExecutor.execute()` (see below). Add short-lived token binding.
- `backend/shared/ai_gateway.py`
  - Keep regex patterns but tag them clearly as "heuristic." Add a documented hook point for plugging in an LLM-based classifier behind a `settings.gateway_llm_classifier_enabled` flag (no implementation here; just the interface, so the claim is honest).
  - Fix false-positive on `pii_internal_ip` for the literal `127.0.0.1` (currently not matched) and `0.0.0.0` — **exclude** these; also add word boundaries so `192.168.1.1` in the middle of a UUID isn't matched.
- `backend/shared/audit_log.py`
  - Replaces file-based storage with Postgres `AuditLogRow` via `audit_repo`. Keep the hash chain. Add `verify_integrity()` as a Postgres query, and emit an **external copy** to stdout in JSON so external log aggregators can anchor.
  - Add optional KMS/ECDSA signing of each entry hash when `settings.audit_signing_key_arn` is set — documented in `ops/SECURITY.md`.
- `backend/shared/circuit_breaker.py`
  - Add `asyncio.Lock` around `record_usage()` and `is_tripped` reads; protect the cost window reset.
- `backend/shared/agent_throttle.py`
  - Same — `asyncio.Lock` wrapping the counters dict.
- `backend/shared/security.py`
  - Consolidate `validate_path()` as the single chokepoint; `read_only_tools`, `active_tools`, `patch_tool` should call it instead of reimplementing. Keep a unit test enforcing no direct `os.path.realpath` outside this module.
- `backend/watcher/log_watcher.py`
  - `_check_file`: read the file in binary mode, decode with `codecs.iterdecode()` chunk-by-chunk to avoid splitting UTF-8 mid-character; track offset after successful decode.
  - Detect rotation via `os.fstat(f.fileno()).st_ino` cached in `_file_positions` values (now a `(offset, inode)` tuple); reset when inode changes.
  - Cap event-queue back-pressure: on `QueueFull`, increment a counter metric and sample-log, not error-log.
  - Change `start()` to return the task handle instead of orphaning it; wire into `ServiceContainer.shutdown()` for clean cancellation.
- `backend/memory/store.py`
  - Either keep as secondary/fallback (JSON file) or deprecate; add `warnings.warn("deprecated — use PostgresMemoryRepo")` when instantiated. Replace by `PostgresMemoryRepo` in the container.
  - Meanwhile, make file writes atomic: write to `path.tmp`, `fsync`, `os.replace()`; protect with `fcntl.flock` (Linux) when present.
- `backend/tools/executor.py`
  - Line 101 `execute()` — accept and enforce `credential: JITCredential`; `self._vault.verify_credential(credential.credential_id, credential.agent_id, f"tool:{tool_name}")`. Reject otherwise.
  - Line 62 `__init__` — take `telemetry: Telemetry` and emit `tool_calls_total` / duration histogram.
- `backend/tools/patch_tool.py`
  - Delete duplicate path validation — use `SecurityGuard.validate_path()` only.
  - `_try_git_apply` path for the temp file should live inside `project_root`-adjacent tmp dir to avoid cross-device issues when `/tmp` is a different mount.
- `backend/tools/restart_tool.py` — (unread; reviewed via subagent)
  - Add structural timeout + explicit `shell=False`; refuse service names containing shell metacharacters; record OTel span.
- `backend/tools/read_only_tools.py`, `backend/tools/active_tools.py`
  - Use `SecurityGuard.validate_path()` / `validate_command()` only; delete in-module duplicates.
- `backend/shared/config.py`
  - Becomes a thin compatibility shim over `backend/shared/settings.py`. Fail-fast validation happens in `Settings.__init__`. Remove silent defaults for `ANTHROPIC_API_KEY`, gateway URL, `PROJECT_ROOT` (must be explicit).
- `backend/Dockerfile`
  - **Remove `usermod -aG root sentry` (line 59)** — critical privilege escalation.
  - Remove `docker` binary download; we will not call the Docker socket anymore (see below).
  - Use multi-stage build with explicit `--chown=sentry:sentry` on the `COPY`. Pin `python:3.12-slim` by digest.
  - Add `HEALTHCHECK` using `curl` at `/api/ready` (liveness stays at `/api/health`).
- `backend/.dockerignore`
  - Add `**/*.log`, `**/.env*`, `htmlcov/`, `.coverage`, `.pytest_cache/`, `__pycache__/`, `.git/`.
- `docker-compose.yml`
  - **Remove `/var/run/docker.sock` volume (line 19).** Replace the `restart_service` tool with direct `systemctl`/`docker compose restart` issued **outside** the sandbox (out of scope — document in RUNBOOK).
  - Mount `${SERVICE_HOST_PATH}` with `:ro` by default; add a second, narrowly scoped writable volume `sentry-patchable-paths:/app/patchable` that `apply_patch` is restricted to.
  - Add `cap_drop: [ALL]`, `cap_add: []`, `pids_limit: 512`, `mem_limit: 2g`, `cpus: "2"`, `logging: driver: json-file, options: { max-size: 10m, max-file: "5" }`.
  - Add `postgres`, `prometheus`, `grafana`, `otel-collector` services. Expose Grafana on `:3030` behind basic-auth, Postgres not exposed externally.
  - Secrets: use `secrets:` blocks (Docker Swarm compatible) bound to files in `./secrets/` (gitignored); fallback env vars for local dev.
- `frontend/nginx.conf`
  - Tighten CSP: remove `'unsafe-inline'` for scripts; allow styles only from self + inline hashes; add `Permissions-Policy`, `Cross-Origin-Opener-Policy`.
  - Add `limit_req_zone` + `limit_req` for `/api/`.
  - Enable gzip + brotli for JS/CSS/JSON.
- `frontend/src/App.jsx`
  - Reduce to ~100 lines: layout + routing only. Sub-components live in `frontend/src/components/`. Wrap tree in `<ErrorBoundary/>`.
- `frontend/package.json`
  - Pin all deps; add `vitest`, `@testing-library/react`, `eslint`, `prettier`.
- `.env.example`
  - Add: `DATABASE_URL`, `API_AUTH_TOKEN` (dev only), `OTEL_EXPORTER_OTLP_ENDPOINT`, `PROMETHEUS_ENABLED`, `AUTO_COMMIT_ENABLED`, `ORCHESTRATOR_TIMEOUT_SECONDS`, `ALLOWED_PATCH_PATHS` (glob list restricting `apply_patch`), `SECRETS_BACKEND` (`env|file|sops|vault`), `SECRETS_VAULT_ADDR`, `SECRETS_VAULT_ROLE`, `SECRETS_SOPS_FILE`.
  - Document that `ANTHROPIC_API_KEY` / Bedrock creds and `API_AUTH_TOKEN` should be loaded from the chosen open-source secrets backend (HashiCorp Vault OSS / OpenBao, sops-age, or docker-compose `secrets:` files) in production; `.env` is only for dev.
- `pytest.ini`, `.coveragerc`
  - Migrate to `pyproject.toml`. Add a separate `tests/integration/` marker requiring a Postgres service (skipped unless `SENTRY_IT=1`).
- `README.md` — update for new env vars, new deployment topology (backend + postgres + prometheus + grafana), and revise Zero-Trust claims table to reflect the post-hardening reality; point to `ops/SECURITY.md` for the real threat model.

**Deleted files**

- `backend/agents/supervisor.py` — dead code. The graph (`backend/orchestrator/graph.py`) does its own routing via `_route_after_triage` / `_route_after_verification`. The `SupervisorAgent` class has **zero non-test imports** (`grep -r SupervisorAgent backend | grep -v test` returns nothing). Remove it and its test in `backend/tests/test_agents.py` (TestSupervisor class) — retain route-function tests by moving `route_after_triage`/`route_after_verification` as pure functions into `backend/orchestrator/graph.py`.
- `backend/memory/store.py` — after migration cut-over: delete the JSON store and its tests. Until then, keep but deprecate.

[Functions]
Fix the broken lifecycle, remove duplicated helpers, and add the handful of functions that enable auth, persistence, and observability.

**New functions**

- `backend/shared/principal.py::Principal.from_token(token: str, db: AsyncSession) -> Principal | None`
  - Purpose: look up an `ApiTokenRow` by SHA-256 hash of the provided bearer token; return `None` on miss or revocation.

- `backend/api/auth.py::require_scope(*scopes: str) -> Callable[[Principal], Principal]`
  - Purpose: FastAPI dependency factory. Used as `@router.post(..., dependencies=[Depends(require_scope("incidents:trigger"))])`.
  - Raises `HTTPException(403)` if `Principal.scopes` missing any required scope.

- `backend/api/auth.py::issue_token(name: str, role: str, scopes: list[str], db: AsyncSession) -> tuple[str, ApiTokenRow]`
  - Purpose: CLI-invoked helper to mint initial admin token at bootstrap (`python -m backend.scripts.create_admin_token`).

- `backend/shared/container.py::build_container(settings: Settings) -> ServiceContainer`
  - Purpose: composition root. Single place that instantiates every dependency. Replaces the scattered globals in `backend/api/app.py:60-68`.

- `backend/shared/container.py::get_container(request: Request) -> ServiceContainer`
  - FastAPI dependency returning `request.app.state.container`.

- `backend/shared/observability.py::init_telemetry(settings) -> Telemetry`
  - Purpose: configure OpenTelemetry SDK, Prometheus exporter, instrument FastAPI + httpx + asyncpg.

- `backend/shared/observability.py::Telemetry.span(name: str, **attrs) -> contextlib.AbstractContextManager[Span]`
  - Purpose: ergonomic span helper used from engine, graph, agents, tools.

- `backend/shared/secrets.py::ISecretsProvider.get(name: str) -> str`
  - Purpose: unified secret lookup. Open-source implementations:
    - `EnvSecrets` reads `os.environ[f"SECRET_{name}"]` (dev only).
    - `FileSecrets` reads `/run/secrets/{name}` (docker-compose `secrets:` / tmpfs).
    - `SopsSecrets` looks up `name` in a sops-age-encrypted YAML decrypted at startup via the `sops` CLI.
    - `VaultSecrets` reads `secret/data/sentry/{name}` from HashiCorp Vault OSS / OpenBao via `hvac` with token or AppRole auth (cached 5 min, invalidated on lease expiry).

- `backend/persistence/session.py::get_session() -> AsyncIterator[AsyncSession]`
  - FastAPI dependency yielding an async SQLAlchemy session.

- `backend/persistence/repositories/incident_repo.py::IncidentRepository.dedupe_fingerprint(fingerprint: str, window_seconds: int) -> bool`
  - Purpose: check whether an identical fingerprint has been seen within the window. Protects against log-storm amplification (the single worst cost-leak today).

- `backend/persistence/repositories/incident_repo.py::IncidentRepository.save(incident: Incident) -> None`
- `backend/persistence/repositories/incident_repo.py::IncidentRepository.transition(incident_id: str, new_state: IncidentState) -> None`
- `backend/persistence/repositories/incident_repo.py::IncidentRepository.list_active() -> list[Incident]`
- `backend/persistence/repositories/incident_repo.py::IncidentRepository.list_resolved(limit: int = 20) -> list[Incident]`
- `backend/persistence/repositories/incident_repo.py::IncidentRepository.get(incident_id: str) -> Incident | None`

- `backend/persistence/repositories/audit_repo.py::PostgresAuditLog.log_action(...)` — same signature as `ImmutableAuditLog.log_action` to be a drop-in.

- `backend/api/v1/routers/stream.py::incidents_sse(request: Request, container = Depends(get_container), _ = Depends(require_scope("incidents:read"))) -> EventSourceResponse`
  - Purpose: server-sent events feed of incident updates. The orchestrator broadcasts to an `asyncio.Queue` per subscriber.

- `backend/watcher/log_watcher.py::LogWatcher._decode_chunk(chunk: bytes) -> tuple[str, bytes]`
  - Purpose: decode UTF-8 safely across chunk boundaries; return decoded text + any trailing bytes to re-buffer. Fixes the partial-codepoint bug.

**Modified functions**

- `backend/orchestrator/engine.py::Orchestrator.handle_event` — rewrite body:
  1. compute fingerprint, call `incident_repo.dedupe_fingerprint`
  2. persist incident immediately (state=TRIAGE)
  3. wrap graph invocation in `asyncio.wait_for(...)` + `try/finally`
  4. **always remove from `_active_incidents` in `finally`** (this is the ESCALATED leak fix)
  5. persist terminal state transition
  6. emit `incidents_total{state=...}` counter.

- `backend/tools/executor.py::ToolExecutor.execute` — add required parameter `credential: JITCredential`. Call `self._vault.verify_credential(...)` first; reject with `audit("cred_verify_failed")`. This makes the NHI/vault actually enforcing.

- `backend/agents/base_agent.py::BaseAgent._call_llm` / `_call_tool` — issue + pass credentials; revoke on exit in `finally`. Remove today's "mint + immediately revoke without use" antipattern.

- `backend/memory/store.py::JSONMemoryStore._write_raw` — atomic write via `tmp + fsync + os.replace` (still used as dev fallback).

- `backend/watcher/log_watcher.py::LogWatcher._check_file` — rotation detection via inode; chunked UTF-8 decode via `_decode_chunk`.

- `backend/watcher/log_watcher.py::LogWatcher.start` — return the asyncio task (today it orphans it at line 35). Owner (`ServiceContainer`) keeps the handle for clean shutdown.

- `backend/shared/ai_gateway.py::AIGateway.scan_output` — filter out RFC-allowed internal probes (127.0.0.1, ::1, 0.0.0.0); add word boundaries to IPv4 pattern; avoid redacting timestamp-like strings.

- `backend/shared/circuit_breaker.py::CostCircuitBreaker.record_usage` and `is_tripped` — wrap in `asyncio.Lock`. Same in `RateLimiter.is_allowed`.

- `backend/api/app.py::lifespan` — rebuild using `build_container(settings)`, start watcher task through the container, instrument with telemetry, no more module-level globals.

**Removed functions**

- `backend/agents/supervisor.py::route_after_triage`, `route_after_verification`, `SupervisorAgent.route`.
  - Reason: dead code. Migration: keep the two pure routing functions and relocate them into `backend/orchestrator/graph.py` (they already have near-duplicates there at lines 407–419). The graph version wins; delete the supervisor versions.

- `backend/shared/security.py` helper duplicates in `backend/tools/*.py` (inlined path/URL checks) — remove; call `SecurityGuard` directly.

[Classes]
Introduce persistence repositories, a service container, a telemetry holder, a settings class, and a Principal — no large class rewrites; existing agent/engine classes retain their public shape.

**New classes**

- `backend.shared.settings.Settings(BaseSettings)` — Pydantic v2 settings. Required-at-startup validation.
- `backend.shared.principal.Principal` — frozen dataclass.
- `backend.shared.container.ServiceContainer` — DI container.
- `backend.shared.observability.Telemetry` — OTel + Prometheus facade.
- `backend.shared.secrets.ISecretsProvider`, `.EnvSecrets`, `.FileSecrets`, `.SopsSecrets`, `.VaultSecrets` (all open-source).
- `backend.persistence.models.IncidentRow`, `.MemoryEntryRow`, `.AuditLogRow`, `.ApiTokenRow`.
- `backend.persistence.repositories.incident_repo.IncidentRepository` (implements new interface `IIncidentRepository` added to `backend/shared/interfaces.py`).
- `backend.persistence.repositories.memory_repo.PostgresMemoryStore(IMemoryStore)`.
- `backend.persistence.repositories.audit_repo.PostgresAuditLog` (implements the same public API as `ImmutableAuditLog`).
- `backend.api.middleware.AuthMiddleware(BaseHTTPMiddleware)`.
- `backend.api.middleware.TimingMiddleware(BaseHTTPMiddleware)` — OTel span + Prometheus histogram per request.
- `frontend.src.components.ErrorBoundary` — React error boundary.

**Modified classes**

- `backend.shared.interfaces` — add `IIncidentRepository`. `IMemoryStore` unchanged (Postgres impl satisfies it).
- `backend.orchestrator.engine.Orchestrator` — gains `_incident_repo: IIncidentRepository`, `_telemetry: Telemetry`, `_broadcaster: IncidentBroadcaster`. Constructor signature gains keyword args (all optional for backward-compat in tests).
- `backend.orchestrator.graph.IncidentGraphBuilder` — gains `_agent_factory: AgentFactory` so agents are constructed once per-build rather than per-event.
- `backend.tools.executor.ToolExecutor` — constructor gains `telemetry` + (optional) `vault`; `execute()` signature adds `credential`.
- `backend.agents.base_agent.BaseAgent` — `__init__` gains `telemetry`; `_call_llm` / `_call_tool` use credentials and spans.
- `backend.watcher.log_watcher.LogWatcher` — `_file_positions: dict[str, tuple[int, int]]` (offset + inode); `start()` returns the task.
- `backend.memory.store.JSONMemoryStore` — marked deprecated; atomic write; still passes existing tests.

**Removed classes**

- `backend.agents.supervisor.SupervisorAgent` — dead; replaced by graph routing.
- (Optional P3) `backend.memory.store.JSONMemoryStore` — once Postgres migration is cut over and integration tests green, delete.

[Dependencies]
Add a small set of well-maintained dependencies; pin everything; track via Dependabot.

Backend (`backend/requirements.txt` → migrate to `pyproject.toml` + `uv`/`pip-tools`):

- Added:
  - `pydantic-settings>=2.2,<3`
  - `sqlalchemy[asyncio]>=2.0.29,<3`
  - `asyncpg>=0.29,<0.30`
  - `alembic>=1.13,<2`
  - `prometheus-client>=0.20,<0.22`
  - `opentelemetry-api>=1.24`, `opentelemetry-sdk>=1.24`, `opentelemetry-instrumentation-fastapi`, `opentelemetry-instrumentation-httpx`, `opentelemetry-instrumentation-asyncpg`, `opentelemetry-exporter-otlp-proto-grpc`
  - `structlog>=24.1`
  - `sse-starlette>=2.1,<3`
  - `hvac>=2.3,<3` (optional, only when `SECRETS_BACKEND=vault` — HashiCorp Vault OSS / OpenBao client, MPL-2.0 license).
  - `argon2-cffi>=23.1` — hashing for API tokens at rest (belt-and-braces; the stored value is SHA-256 of the token, but argon2 for new-format tokens supports rotation).
- Removed / kept as-is:
  - Keep `anthropic`, `httpx`, `gitpython`, `langgraph`.
- Dev / test:
  - `ruff`, `mypy`, `types-PyYAML`, `pytest-postgresql` (integration tests), `httpx[cli]`.

Frontend (`frontend/package.json`):

- Added: `vitest`, `@testing-library/react`, `@testing-library/jest-dom`, `eslint`, `prettier`, `eventsource-parser` (for SSE), `zustand` (small state library to avoid prop-drilling in split components).
- Pin all versions.

Infra (all OSS images):

- `postgres:16-alpine` — PostgreSQL (OSI-approved PostgreSQL License). Sidecar.
- `prom/prometheus:v2.52.0` — Prometheus (Apache-2.0). Sidecar.
- `grafana/grafana-oss:10.4.3` — Grafana OSS (AGPLv3); we use the `grafana-oss` image rather than the enterprise one to stay on the fully open-source edition. Sidecar.
- `otel/opentelemetry-collector-contrib:0.101.0` — OpenTelemetry Collector (Apache-2.0). Optional; default off.
- `openbao/openbao:2.0` (MPL-2.0) — recommended open-source secrets store, Linux Foundation community fork of Vault. Optional sidecar enabled only when `SECRETS_BACKEND=vault`. Users who prefer upstream `hashicorp/vault:1.17` (BUSL-1.1 since 2023) can swap the image; the `hvac` client speaks to both. Document both choices in `ops/SECURITY.md`.

CI:

- GitHub Actions actions: `actions/checkout@v4`, `actions/setup-python@v5`, `actions/setup-node@v4`, `aquasecurity/trivy-action@0.20.0`, `anchore/sbom-action@v0.15`.

[Testing]
Tests split into fast unit tests (mocked deps) and integration tests (real Postgres in CI), with explicit regression tests for every bug fixed in P0.

- **Existing 442 tests stay green.** Every module refactor must keep existing imports working or ship a compatibility shim.
- **New regression tests (P0 — one per fixed bug):**
  - `backend/tests/integration/test_escalated_cleanup.py` — drive the orchestrator to ESCALATED via a forced exception and assert `_active_incidents` is empty and `IncidentRepository` contains exactly one row in state ESCALATED.
  - `backend/tests/integration/test_watcher_concurrent_start.py` — spawn 10 concurrent `POST /api/watcher/start` calls; assert only one task is running and none are leaked.
  - `backend/tests/test_memory_atomic_write.py` — simulate `os.replace` racing; assert file is either fully old or fully new, never partial.
  - `backend/tests/test_watcher_rotation.py` — rotate a log file mid-read; assert events from both old and new file, none missed, none duplicated.
  - `backend/tests/test_watcher_partial_utf8.py` — write a 3-byte UTF-8 character split across two polls; assert no `UnicodeDecodeError`.
  - `backend/tests/test_vault_credential_enforced.py` — ToolExecutor rejects a forged credential; asserts audit entry was written.
  - `backend/tests/test_incident_dedup.py` — same fingerprint within 60s yields one incident.
- **New integration tests (P1/P2):**
  - `backend/tests/integration/test_api_auth.py` — unauthenticated request → 401; wrong scope → 403; revoked token → 401.
  - `backend/tests/integration/test_orchestrator_persistence.py` — restart backend mid-incident, verify state recovered.
  - `backend/tests/integration/test_end_to_end.py` — watcher detects a forced error line → incident persisted → resolved → memory updated → SSE event delivered.
  - `backend/tests/integration/test_metrics.py` — after one incident, `incidents_total{state="resolved"} >= 1`, `llm_cost_usd_total > 0`.
- **Frontend tests (P3):**
  - `frontend/src/components/__tests__/*.test.jsx` for each component with Vitest + Testing Library.
- **Coverage:**
  - Update `.coveragerc`/`pyproject.toml` to require `--cov-fail-under=90` for the backend. Integration tests run in a CI step behind `SENTRY_IT=1`.
- **Mutation testing (optional P3):**
  - Add `mutmut` config and a nightly workflow to catch weak assertions.
- **Contract test:**
  - `backend/tests/test_openapi_snapshot.py` — snapshot the generated OpenAPI JSON and compare to `backend/frontend_contract/openapi_snapshot.json`; fails on unexpected API change.

[Implementation Order]
Sequence changes to minimize merge conflicts, keep tests green at every step, and ship value incrementally.

1. **P0.1 — Delete dead code + fix lifecycle bugs (no infra changes).**
   - Remove `backend/agents/supervisor.py`; move `route_*` functions into `graph.py` if not already there (they are); delete `TestSupervisor*` tests.
   - Fix ESCALATED cleanup in `engine.py` (always delete from `_active_incidents` in `finally`).
   - Replace `_resolved_incidents: list` with `collections.deque(maxlen=MAX_RESOLVED_INCIDENTS)`.
   - Add atomic writes to `memory/store.py` (tmp + fsync + os.replace).
   - Fix watcher UTF-8 chunk decoding + inode-based rotation detection.
   - Add `asyncio.Lock` to `CostCircuitBreaker` and `RateLimiter`.
   - Wire watcher `start()` to return its task; `app.py` lifespan owns it.
   - Add regression tests for each of the above.
   - **Exit criteria:** existing tests green + new regression tests green.

2. **P0.2 — Docker hardening.**
   - Delete `usermod -aG root sentry` from `backend/Dockerfile`.
   - Remove `/var/run/docker.sock` mount from `docker-compose.yml`; disable `restart_service` until replaced (keep tool but in AUDIT-only).
   - Mount `SERVICE_HOST_PATH` with `:ro`; add narrow writable `sentry-patchable-paths` volume.
   - Add `cap_drop: [ALL]`, `pids_limit`, `mem_limit`, `cpus`, `logging` driver config.
   - **Exit criteria:** `docker compose up` succeeds; manual test of watcher + trigger endpoint; security scan clean (Trivy).

3. **P1.1 — Container + settings + typed config. [✓ DONE]**
   - ✅ Introduced `backend/shared/settings.py` (pydantic-settings v2 with a dataclass fallback). `Settings.to_app_config()` projects back to the legacy `AppConfig` so downstream code keeps working.
   - ✅ Introduced `backend/shared/container.py::ServiceContainer` holding every singleton + a `shutdown()` that cancels the watcher dispatch task.
   - ✅ Introduced `backend/shared/factory.py::build_container(settings, llm_override=...)` — the single composition root. Previously duplicated across `api/app.py::lifespan` and `tests/e2e/conftest.py::build_live_stack`; both now call this.
   - ✅ Refactored `backend/api/app.py` to a `create_app(container=None)` factory:
     - Production path (`container=None`): lifespan builds the container and attaches it to `app.state.container`.
     - Test path (`container=`): container supplied up-front; no lifespan re-build.
     - Each handler reads its dependencies via a `_pick(request, attr, global_name)` helper that prefers the container and falls back to the legacy module globals so `patch("backend.api.app._orchestrator", ...)` in the existing unit tests keeps working.
   - ✅ `backend/tests/e2e/conftest.py` now drives the REAL `create_app(container=stack.container)` — the hand-rolled in-process app is gone. E2E tests exercise production routes exactly.
   - ✅ `pydantic-settings>=2.0.0,<3.0.0` added to `backend/requirements.txt`.
   - **NOTE:** Legacy module-level `_orchestrator`/`_watcher`/`_config` globals are retained **as a back-compat shim only** (see P1.1 note at the top of `backend/api/app.py`). They are populated by lifespan and used as fallback for ~30 existing unit tests that still `patch()` them. They will be removed in P1.2 once those tests migrate to container fixtures.
   - **Exit criteria met:** full suite 580 passed / 6 skipped / 9 xfailed / 0 failed (up from 579 — P1.1 flipped SEC-41 from xfail to passing because `create_app(container=...)` now ships the real RequestIDMiddleware).

4. **P1.2 — Postgres persistence. [✓ DONE]**
   - ✅ `backend/persistence/models.py` — SQLAlchemy 2.0 ORM: `IncidentRow`, `MemoryEntryRow`, `MemoryStateRow`, `AuditLogRow`, `ApiTokenRow`. Portable between Postgres (asyncpg) and SQLite (aiosqlite).
   - ✅ `backend/persistence/session.py` — `build_database(url)` factory producing an async engine + sessionmaker. Logs the URL with password redacted.
   - ✅ `backend/persistence/repositories/memory_repo.py::PostgresMemoryRepo` — drop-in for `JSONMemoryStore` (implements the same `IMemoryStore` contract + `set_fingerprint`/`get_fingerprint`).
   - ✅ `backend/persistence/repositories/audit_repo.py::PostgresAuditLog` — drop-in for `ImmutableAuditLog` with the same hash-chain integrity guarantees. `timestamp_iso` is stored verbatim alongside the DateTime column so `verify_integrity()` stays lossless across DB round-trips.
   - ✅ `backend/persistence/repositories/incident_repo.py::IncidentRepository` — full persistence for every `Incident` state transition: `save(incident, fingerprint=)`, `transition(id, state)`, `get(id)`, `list_active()`, `list_resolved(limit)`, plus **`dedupe_fingerprint(fp, window_seconds)`** and the canonical `compute_fingerprint(event)` helper (both needed by P1.3).
   - ✅ Alembic migration structure under `backend/persistence/migrations/` — initial revision creates every table + indexes + the Postgres-only `audit_log` append-only trigger. SQLite branches are marked so batch ALTER works. Verified with `alembic upgrade head` and `alembic downgrade base` against SQLite.
   - ✅ `backend/shared/factory.py` — `build_container` now branches on `settings.database_url`:
     * non-empty → build SQLAlchemy engine, use `PostgresMemoryRepo`/`PostgresAuditLog`/`IncidentRepository`.
     * empty (default) → legacy `JSONMemoryStore` + `ImmutableAuditLog`, no DB connection opened.
   - ✅ `ServiceContainer.database` + `.incident_repo` fields added; `shutdown()` disposes the engine.
   - ✅ `docker-compose.yml` — added `postgres:16-alpine` sidecar with health-check, named volume `sentry-postgres-data`, `depends_on: service_healthy` for the backend. Port **not** exposed to the host by default.
   - ✅ `.env.example` — `DATABASE_URL` documented with both Postgres and SQLite examples; blank keeps legacy mode.
   - ✅ `backend/tests/test_persistence.py` — 20 new unit tests exercising every repo against a per-test SQLite file. Suite is 600 passed / 6 skipped / 9 xfailed / 0 failed.
   - **Exit criteria met.** Orchestrator does NOT yet write through `incident_repo` — that's an additive P1.3 step (the repo exists, the schema exists, the switch is a single line in `engine.handle_event`). Leaving that as the first deliverable of P1.3 keeps this PR reviewable.

5. **P1.3 — Orchestrator timeouts + dedup. [✓ DONE]**
   - ✅ `backend/orchestrator/engine.py`:
     * New ``_compute_event_fingerprint(event)`` + ``_is_duplicate(fp)``. Dual-backend: uses ``self._incident_repo.dedupe_fingerprint(fp, window_seconds=...)`` when the Postgres path is active; falls back to an ``asyncio.Lock``-protected in-memory cache otherwise. Stale entries trimmed lazily at 2× the window.
     * ``handle_event`` now checks the fingerprint first and returns ``None`` on a dedup hit — no LLM spend, no new incident row.
     * Graph invocation wrapped in ``asyncio.wait_for(self._graph.ainvoke(...), timeout=self._orch_timeout)``. On ``TimeoutError`` the incident is marked ``ESCALATED``, the audit log records ``orchestrator_timeout``, and the ``finally`` block still drains ``_active_incidents`` and persists the terminal state.
     * New optional kwargs: ``incident_repo``, ``orchestrator_timeout_seconds`` (default 300), ``dedup_window_seconds`` (default 60). All backward-compatible — existing unit tests construct ``Orchestrator`` without them and keep working.
   - ✅ `backend/shared/factory.py::build_container` now passes ``incident_repo=incident_repo, orchestrator_timeout_seconds=settings.orchestrator_timeout_seconds`` when constructing the ``Orchestrator``.
   - ✅ **CONC-03** log-storm dedup: 50 identical LogEvents in an ``asyncio.gather`` → exactly 1 resolved incident (flipped xfail → passing).
   - ✅ **CONC-08** orchestrator timeout: slow Triage LLM (5 s sleep) + ``_orch_timeout=1`` → incident ends ESCALATED in well under 2.5 s (flipped xfail → passing).
   - ✅ **FN-storm** serial variant (10 sequential identical triggers → 1 incident) also flipped xfail → passing.
   - **Exit criteria met.** Full suite: 603 passed / 6 skipped / 6 xfailed / 0 failed.

6. **P1.4 — Vault credentials actually enforced. [✓ DONE]**
   - ✅ `backend/shared/vault.py`: `LocalVault.verify_credential(credential_id, agent_id, scope)` was already implemented — confirmed semantics (returns `False` on unknown id, revoked/expired, agent mismatch, or scope mismatch).
   - ✅ `backend/tools/executor.py`:
     * `ToolExecutor.__init__` now accepts optional `vault: Optional[IVault] = None`.
     * `ToolExecutor.execute(..., credential: Optional[JITCredential] = None)`.
     * When `self._vault is not None`, every call MUST present a vault-issued credential whose `scope == f"tool:{tool_name}"`. Missing, forged, scope-mismatched, wrong-agent, expired, or revoked credentials are hard-rejected BEFORE any other gate (AUDIT / DISABLED / STOP_SENTRY / registry ACL / validation), and an audit entry `tool_blocked` (`no_credential`) or `cred_verify_failed` is written.
     * When `self._vault is None` the pre-P1.4 behaviour is preserved — legacy unit tests that construct `ToolExecutor(security, project_root)` without a vault remain green.
   - ✅ `backend/agents/base_agent.py::_call_tool`:
     * Before dispatching to the executor, issues a JIT credential via `self._vault.issue_credential(self.agent_id, scope=f"tool:{tool_name}", ttl_seconds=30)`.
     * Passes the credential to `executor.execute(..., credential=cred)`.
     * Revokes the credential in `finally` regardless of success — one credential per call, no replay.
   - ✅ `backend/shared/factory.py::build_container` now wires `vault=vault` into `ToolExecutor`, so every production / E2E stack enforces credentials end-to-end.
   - ✅ **SEC-23..26 flipped xfail → passing**: added `test_sec23_tool_without_credential_rejected`, `test_sec24_agent_path_issues_and_verifies_credential`, `test_sec25_forged_credential_rejected` (real assertion), `test_sec26_scope_mismatch_rejected`, plus `test_sec26b_revoked_credential_rejected` for replay-after-revoke.
   - ✅ **Unit regressions**: new `TestVaultCredentialEnforcement` class in `test_p0_regressions.py` covering missing / forged / scope-mismatched / revoked / wrong-agent / valid-credential / legacy-no-vault cases — 7 focused unit tests that lock this contract in.
   - **Exit criteria met.** Full suite: **615 passed / 6 skipped / 5 xfailed / 0 failed** (was 603/6/6/0 at P1.3).
   - *Note on LLM-call credentials:* the original P1.4 spec also mentioned a credential wrapper around LLM calls. That stays deferred into P2.2 (secrets backend), because once secrets come from a proper secrets provider the natural place to attach a per-call scope is the `ILLMClient` wrapper that reads the API key from `ISecretsProvider`, not an orthogonal vault layer. Documented here to avoid scope creep.

7. **P2.1 — Auth. [✓ DONE]**
   - ✅ `backend/shared/principal.py` — `Principal` frozen dataclass + `hash_token`, `constant_time_equals`, `generate_token` helpers. ``"*"`` scope = admin wildcard.
   - ✅ `backend/api/auth.py`:
     * `TokenRegistry` — in-memory ``sha256(raw) → Principal`` + separate revocation set. Tokens never stored in plain text. Thread-safe via `threading.Lock`.
     * `AuthMiddleware` — runs before every non-`/api/health` route. Matrix: no header → 401 (auth on) / passthrough (dev); bad header → 400; `?token=` in query → 400 (SEC-04); unknown → 401 (auth on) / passthrough (dev); revoked → 401; valid → attaches `request.state.principal`.
     * `require_scope(*scopes)` — FastAPI dependency factory: 401 if no principal when auth enabled, 403 on missing scope, no-op when registry empty (dev mode).
     * `seed_tokens_from_settings` — converts legacy `API_AUTH_TOKEN` env var into a default admin principal at startup.
   - ✅ `backend/shared/container.py` — new `auth_tokens: TokenRegistry` field.
   - ✅ `backend/shared/factory.py` — `build_container` instantiates the registry and seeds it from `settings.api_auth_token` so production `docker compose up` with `API_AUTH_TOKEN` set auto-enforces auth, while dev runs (no token) remain open.
   - ✅ `backend/api/app.py`:
     * `AuthMiddleware` registered in `create_app` (order matters — outer `RequestIDMiddleware`, then `AuthMiddleware`, then CORS).
     * Every route except `/api/health` gets `dependencies=[Depends(require_scope(...))]` with an appropriate scope: `incidents:read` for GET, `incidents:trigger` for POST /api/trigger, `watcher:control` for watcher start/stop.
   - ✅ **Auth is auto-disabled when the registry is empty.** The ~500 existing unit/E2E tests that don't provision a token continue to pass in "dev mode"; only the explicitly-auth-enabled tests (SEC-01..04) exercise the 401/403/400 paths.
   - ✅ **SEC-01, SEC-02, SEC-03 flipped xfail → passing.** New tests added:
     * `test_sec01_unauthenticated_trigger_is_rejected` — 401 when no header.
     * `test_sec01b_unauthenticated_read_is_rejected` — read endpoints also demand a token.
     * `test_sec01c_health_is_open_even_with_auth_enabled` — `/api/health` exempt for liveness probes.
     * `test_sec02_wrong_scope_is_rejected` — read-only token → 403 on POST /api/trigger.
     * `test_sec02b_correct_scope_is_accepted` — admin token (scope `*`) accepted.
     * `test_sec03_revoked_token_is_rejected` — 401 with "revoked" in body.
     * `test_sec04_token_in_query_is_rejected` — 400 (prevents access-log leakage; new scenario beyond the xfail suite).
     * `test_sec04b_malformed_authorization_header_rejected` — wrong scheme → 400.
   - ✅ New `backend/tests/test_auth.py` (28 unit tests) covering `Principal.has_scope`, `hash_token` determinism, `constant_time_equals`, `generate_token`, `TokenRegistry` add/resolve/revoke/clear/re-add/no-plaintext-storage, `seed_tokens_from_settings` on empty / populated / attr-missing settings, and `require_scope` for dev-mode / 401 / 403 / matching / wildcard / multi-scope paths.
   - **Deferred to later phases (documented honestly):**
     * Postgres-backed `ApiTokenRow` persistence (the ORM row already exists from P1.2, but DB-session wiring moves to P2.2 alongside the secrets provider). Until then every deployment has exactly one token from `API_AUTH_TOKEN`.
     * Seed-token CLI (`python -m backend.scripts.create_admin_token`) also moves to P2.2.
     * Frontend bearer-token integration → P3.1.
   - **Exit criteria met.** Full suite: **651 passed / 6 skipped / 2 xfailed / 0 failed** (was 615/6/5/0 at P1.4).

8. **P2.2 — Secrets (open-source only).**
   - `ISecretsProvider` with four OSS implementations: `EnvSecrets` (dev), `FileSecrets` (docker-compose `secrets:` / tmpfs), `SopsSecrets` (sops+age encrypted YAML — fully offline, GitOps-friendly), `VaultSecrets` (HashiCorp Vault OSS / OpenBao via `hvac`). Swappable via `SECRETS_BACKEND=env|file|sops|vault`.
   - Move `ANTHROPIC_API_KEY`, `API_AUTH_TOKEN`, `DATABASE_URL` behind the provider.
   - Ship an example OpenBao compose service as a documented optional sidecar (disabled by default).
   - Document secret rotation for each backend in `ops/RUNBOOK.md` (e.g. `bao kv put sentry/anthropic_key=new` for Vault/OpenBao, `sops updatekeys secrets.yaml` for sops-age).

9. **P2.3 — Observability.**
   - **P2.3a ✅ DONE** — Split `/api/health` (shallow liveness) vs
     `/api/ready` (readiness: LLM reachable + DB reachable + disk
     writable). Returns 200 when all deps reachable, 503 otherwise with
     per-check booleans in the body. FN-02 E2E flipped from xfail to
     passing. `/api/health` stays open (no auth, no dep checks) for
     Kubernetes `livenessProbe`; `/api/ready` is the pool-drain probe.
   - **P2.3b — DEFERRED** — `Telemetry` facade, OpenTelemetry SDK +
     instrumentation, Prometheus `/metrics` endpoint with counters
     (`incidents_total`, `llm_cost_usd_total`, `tool_calls_total`,
     `watcher_events_total`, `circuit_breaker_trips_total`), structlog
     JSON logs with trace-id correlation, Compose sidecars (Prometheus,
     Grafana with provisioned dashboard, optional OTel Collector).
   - **Exit criteria:** Grafana dashboard shows live incidents, costs, watcher events.

10. **P2.4 — SSE dashboard feed.**
    - Implement broadcaster in `ServiceContainer`; `stream.py` router; frontend `useIncidentStream` hook.
    - Drop client-side polling.

11. **P3.1 — Frontend split + polish.**
    - Break `App.jsx` into components; add `ErrorBoundary`; tighten `nginx.conf` CSP; migrate frontend to TypeScript (optional).
    - Vitest coverage ≥ 80%.

12. **P3.2 — CI/CD.**
    - `.github/workflows/ci.yml` (lint, mypy, pytest, vitest, Trivy, SBOM, image build).
    - `release.yml` tag-driven publish to GHCR.
    - Dependabot.

13. **P3.3 — Documentation & honesty pass.**
    - Revise README Zero-Trust claims table to reflect actual enforcement.
    - `ops/SECURITY.md` — threat model, current gaps, how to extend.
    - `ops/RUNBOOK.md` — operator playbooks.
    - `ops/ARCHITECTURE.md` — update for new topology.

14. **P3.4 — Cleanup.**
    - Delete `JSONMemoryStore` once Postgres has baked for two releases.
    - Delete `memory/store.py` tests; remove dual-write flag.
    - Final pass: `ruff check --fix`, `mypy --strict backend/`, update all doc references.

Each phase ships independently behind feature flags where needed, leaves the 442-test suite green, and is individually reviewable in a single PR.
