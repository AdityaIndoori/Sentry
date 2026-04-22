# Sentry Security Model

**Status:** Post-P2.4 honest threat model. Supersedes the optimistic
"Zero-Trust" marketing table in the pre-P0 README.

Sentry's autonomy gives it tools that can read source code, patch
files, and restart services. This document is the definitive, auditable
record of **what we actually enforce, where the enforcement lives, and
what we do NOT protect against**. Every claim here maps to a test in
[`ops/E2E_TEST_CATALOG.md`](./E2E_TEST_CATALOG.md).

---

## 1. Threat model

Assumed adversary capabilities, from weakest to strongest:

| Tier | Capability                                                                                 | In-scope?           |
|------|--------------------------------------------------------------------------------------------|---------------------|
| T0   | External user with a valid bearer token but limited scopes                                 | ✅ yes              |
| T1   | External user with no token (unauth scan)                                                  | ✅ yes              |
| T2   | Attacker who can inject crafted log lines into a monitored file (prompt injection vector)  | ✅ yes              |
| T3   | Attacker who can trick an LLM via tool outputs into misusing remaining tools               | ✅ yes              |
| T4   | Compromised dependency (Python package supply-chain)                                       | ⚠️ partial (Trivy)   |
| T5   | Attacker with host-level access to the Docker daemon / filesystem                          | ❌ out of scope     |
| T6   | Attacker with the ``ANTHROPIC_API_KEY`` and other secrets                                  | ❌ out of scope     |

---

## 2. Controls — what ships today

### 2.1 Authentication & Authorization (P2.1)

* **Bearer-token auth** (`Authorization: Bearer <token>`) is the single
  entry point. Tokens are stored as `sha256(raw)` in-memory; plaintext
  never hits disk.
* **Scopes**: `incidents:read`, `incidents:trigger`, `watcher:control`.
  The `"*"` scope = admin. Every API route except `/api/health` and
  `/metrics` carries a `Depends(require_scope(...))` dependency.
* **Dev mode**: when the token registry is empty, auth is auto-disabled
  so the 500+ existing unit/E2E tests continue to run without
  provisioning tokens. Production sets `API_AUTH_TOKEN` in the env
  (or in the secrets backend) and auth auto-engages.
* **Tokens in URLs are rejected** (SEC-04: `?token=…` → 400) so they
  never leak into access logs.
* **Not yet:** Postgres-backed multi-token `ApiTokenRow` persistence,
  token-rotation CLI, refresh semantics.

### 2.2 Secrets management (P2.2)

Pluggable via `SECRETS_BACKEND`:

| Backend  | Use case                                        | License        |
|----------|--------------------------------------------------|----------------|
| `env`    | Dev / single-container demo                      | n/a            |
| `file`   | Docker-compose `secrets:` / K8s tmpfs            | n/a            |
| `sops`   | Offline / GitOps with age encryption             | MPL-2.0        |
| `vault`  | HashiCorp Vault OSS / OpenBao (production)       | MPL-2.0        |

All backends implement a common `ISecretsProvider.get(name)` interface.
The `API_AUTH_TOKEN` (P2.1) is hydrated from the provider at startup
when the raw env var is empty, so secrets never need to appear in the
env of the backend container.

### 2.3 Zero-Trust primitives

* **NHI Vault** (`backend/shared/vault.py::LocalVault`) mints per-tool
  short-TTL credentials. As of **P1.4**, `ToolExecutor.execute` hard-
  rejects any call without a vault-issued credential whose scope
  matches `tool:<tool_name>`. Covered by SEC-23..26.
* **AI Gateway** (`backend/shared/ai_gateway.py`) scans LLM inputs
  for prompt injection / role hijack / delimiter injection patterns
  and LLM outputs for PII + API keys. SEC-13..17.
  *Honesty note:* this is a **heuristic regex classifier**, not an
  LLM-based one. The plan tags where to plug in a stronger classifier
  if needed; see `settings.gateway_llm_classifier_enabled`.
* **Immutable Audit Log** — hash-chained entries. In JSON mode
  (`DATABASE_URL=""`) the chain lives in a JSONL file; in Postgres
  mode (P1.2) entries are rows and a migration installs an
  append-only trigger that rejects UPDATE/DELETE (SEC-30).
* **Agent Throttle** — per-agent action-rate limiter; defaults to 5
  actions / minute. SEC-32.
* **Tool Registry ACL** — role-based deny-list: Triage can't call
  `apply_patch`; Validator can't call `restart_service`. SEC-27, 28.
* **Cost Circuit Breaker** — trips when per-10-minute LLM spend
  exceeds `MAX_COST_PER_10MIN_USD`. Trip increments
  `sentry_circuit_breaker_trips_total` (P2.3b). SEC-31.
* **Kill switches**: host-level `STOP_SENTRY` file halts every write
  tool; in-process `LocalVault.revoke_all()` invalidates every live
  credential. SEC-21, SEC-22.

### 2.4 Input validation

* Path traversal rejected at `SecurityGuard.validate_path` — used by
  every tool that takes a path. SEC-05..07.
* Command allow-list with base-token matching (not substring) —
  `curl-e` does NOT match `curl`. SEC-08..10.
* URL allow-list with suffix matching — `docs.python.org.evil.com`
  is not a subdomain of `docs.python.org`. SEC-11, 12.

### 2.5 Container isolation (P0.2)

* No `usermod -aG root` in the Dockerfile (the original demo had this).
* No `/var/run/docker.sock` bind-mount — `restart_service` calls out
  to a webhook / socket-proxy / systemctl instead.
* `SERVICE_HOST_PATH` mounted `:ro`; writable scratch is limited to
  a narrowly-scoped `sentry-patchable-paths` volume.
* `cap_drop: [ALL]`, `pids_limit: 512`, `mem_limit: 2g`, `cpus: "2"`,
  bounded `json-file` logging. SEC-35..38.

### 2.6 Observability (P2.3a + P2.3b)

* `/api/health` — shallow liveness (always 200 if the process is
  alive). `/api/ready` — deep readiness (LLM / DB / disk) returning
  503 when any check fails. FN-01, FN-02.
* `/metrics` — Prometheus text exposition:
  `sentry_incidents_total{state}`, `sentry_tool_calls_total{tool,success}`,
  `sentry_llm_calls_total`, `sentry_llm_cost_usd_total`,
  `sentry_watcher_events_total`, `sentry_circuit_breaker_trips_total`.
  When `prometheus_client` is not installed the endpoint returns 503
  and every helper no-ops, so dev machines remain green.
* Every response carries `X-Request-ID` for forensic tracing. SEC-41.

### 2.7 Dashboard — live feed (P2.4)

* `/api/stream/incidents` — Server-Sent Events fed by the orchestrator's
  `IncidentBroadcaster`. Every state transition produces
  `event: incident.created` or `event: incident.updated` with the
  incident dict. Gated by `incidents:read` scope. Replaces the
  5-second polling loop.

---

## 3. What we explicitly do NOT defend against

* **Compromised host.** An attacker with root on the docker host wins.
  Use host-level hardening + monitoring.
* **Compromised ANTHROPIC/OpenAI/Bedrock credentials.** Rotate via the
  secrets backend per the Runbook; the Cost Circuit Breaker limits
  damage but does not prevent it.
* **Prompt injection that the AI Gateway misses.** The heuristic layer
  is best-effort. Every tool call is still bounded by the registry ACL,
  path/command/URL allow-lists, and AUDIT mode. A malicious LLM can at
  worst blow through the cost budget; it cannot escape `PROJECT_ROOT`.
* **LangGraph / LangChain / Anthropic SDK RCE via un-patched CVEs.**
  Mitigated by Dependabot + Trivy (P3.2) but not guaranteed.
* **Timing side channels on auth.** We compare token hashes with
  `hmac.compare_digest`, which is constant-time, but request routing
  and DB lookup are not. Rate-limit behind a reverse proxy for
  production deployments.
* **DDoS against `/metrics` or `/api/stream/incidents`.** Both
  endpoints are unbounded by default; use nginx `limit_req_zone` for
  public-facing deployments.

---

## 4. Security checklist before production rollout

- [ ] `API_AUTH_TOKEN` set via Vault/OpenBao (not `.env`)
- [ ] `DATABASE_URL` → Postgres with TLS
- [ ] nginx TLS termination + HTTPS-only redirect
- [ ] `SERVICE_HOST_PATH` mounted read-only
- [ ] `STOP_SENTRY` file path confirmed on host (not inside container)
- [ ] Prometheus scrape configured against `/metrics`
- [ ] Alertmanager rule on `sentry_circuit_breaker_trips_total > 0`
- [ ] Log aggregation pulling `backend_*.log` (JSON)
- [ ] Weekly `alembic upgrade head` + backup snapshot
- [ ] Quarterly secret rotation per the Runbook
- [ ] Trivy scan clean in CI
- [ ] CycloneDX SBOM attached to each release

---

## 5. Reporting vulnerabilities

Open a GitHub Security Advisory on the repository (preferred) or
email the maintainer listed in `README.md`. We target acknowledgement
in 72 hours.
