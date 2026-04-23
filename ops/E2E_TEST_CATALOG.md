# Sentry End-to-End Test Catalog

This is the master list of every functional and security end-to-end test that must
pass before Sentry is considered production-ready. Each row is a **single scenario**
a test runner must be able to execute against a live `docker compose up` stack
with no mocks.

Test-ID convention: `<area>-<seq>` — `FN-*` for functional, `SEC-*` for security,
`CONC-*` for concurrency, `RES-*` for resilience, `OBS-*` for observability,
`PERF-*` for performance, `OPS-*` for operator / lifecycle.

Every test has: **Pre-conditions**, **Steps**, **Expected outcome**, **Failure mode
that gets caught** (what real-world bug / attack this detects), and a pointer to
the implementing pytest function (once written).

---

## FN — Functional (happy-path + variants)

| ID | Scenario | Pre | Steps | Expected | Catches |
|----|----------|-----|-------|----------|---------|
| FN-01 | Health endpoint is live before anything else is initialized | docker up just after start | `GET /api/health` | 200, `{"status": "ok"}`, no auth required | Liveness probe wrong |
| FN-02 | Readiness distinct from liveness | Full stack up | `GET /api/ready` | 200, LLM reachable + DB reachable + disk writable | Deploy-time readiness lies |
| FN-03 | Status endpoint lists no active incidents on cold start | Cold start | `GET /api/status` (authed) | `active_incidents=0`, `resolved_total=0`, `circuit_breaker.tripped=false` | Stale state |
| FN-04 | Manual trigger → full pipeline → RESOLVED | Vault writable, LLM mocked to return a clean fix | `POST /api/trigger` with a symptom line | 200; `incident.state=resolved`; a `MemoryEntry` exists; audit log has ≥ 4 phase entries | End-to-end orchestration broken |
| FN-05 | Manual trigger → false positive → IDLE | LLM triage returns FALSE_POSITIVE | `POST /api/trigger` | `incident.state=idle`, no diagnosis/remediation phases | Triage gating broken |
| FN-06 | Verification-fail retry loop works | LLM validator returns RESOLVED=false twice, then true; `MAX_RETRIES=3` | Trigger incident | `incident.retry_count==2`, final state RESOLVED | Retry edge never wired |
| FN-07 | MAX_RETRIES exceeded → ESCALATED | Validator always returns false | Trigger incident | `incident.state=escalated`, incident **removed** from `_active_incidents`, memory NOT saved | ESCALATED incident-leak regression |
| FN-08 | Watcher detects log line and fires pipeline | Watcher running; `watched/app.log` monitored | Append an ERROR line to the file | Incident appears in `GET /api/incidents`; fingerprint recorded | Watcher ↔ orchestrator pipe broken |
| FN-09 | Watcher ignores non-matching lines | Watcher running | Append benign INFO lines | No incident created | Watcher regex too loose |
| FN-10 | Watcher detects rotation via inode change | Watcher running against `watched/app.log` | `mv app.log app.log.1 && touch app.log && append ERROR` | New incident fires; reads from new inode | Logrotate silent data loss |
| FN-11 | Watcher detects truncate-in-place rotation | Watcher running | `> app.log; append ERROR` (truncate) | New incident fires | Size-shrink detection broken |
| FN-12 | Watcher survives UTF-8 codepoint split across poll boundary | `_MAX_READ_PER_POLL=5` | Write bytes `hello \xc3` then `\xa9 error\n` | Incident fires with `café error` | UnicodeDecodeError loss |
| FN-13 | Incident details endpoint returns full activity log | Completed incident exists | `GET /api/incidents/{id}` | 200, activity log has `llm_call`, `tool_call`, `tool_result`, `decision`, `phase_start`, `phase_complete` for each phase | Activity trail broken |
| FN-14 | Memory endpoint paginates last 20 entries | 50 resolved incidents | `GET /api/memory` | 20 most-recent entries, fingerprint present | Unbounded list bug |
| FN-15 | Tools endpoint lists all 6 MCP tools | Any time | `GET /api/tools` | 6 tool definitions with input schemas | Tool registry missing |
| FN-16 | Security posture endpoint shows all 5 Zero-Trust layers | Any time | `GET /api/security` | vault/gateway/audit_log/throttle/registry all `active` | Security fixture not wired |
| FN-17 | Config endpoint never leaks secrets | Any time | `GET /api/config` | 200; no `ANTHROPIC_API_KEY`, `API_AUTH_TOKEN`, `DATABASE_URL` | Secret leak |
| FN-18 | Watcher start is idempotent | Watcher already started | Two `POST /api/watcher/start` calls | Second call returns `already_running`; only one task exists | Duplicate event-loop tasks |
| FN-19 | Watcher stop is idempotent | Watcher stopped | Two `POST /api/watcher/stop` calls | Both return `stopped`; no exceptions | Double-stop crash |
| FN-20 | Dashboard SSE stream receives incident updates | Watcher running | Open SSE `/api/stream/incidents` then trigger an incident | SSE event delivered within 2 s of state transition | SSE pipe broken |
| FN-21 | Service Awareness: source-code context injected into triage | `SERVICE_HOST_PATH` mounted | Trigger incident | Agent prompt contains "Source code path" line with the real path | Context injection broken |
| FN-22 | Service Awareness: fingerprint written to memory on startup | Fresh stack, fingerprint unset | Start stack | `MemoryStore.get_fingerprint()` returns non-empty | Fingerprint never populated |
| FN-23 | `apply_patch` creates a `.bak` file | Active mode, valid diff | Surgeon applies patch | `file.bak` exists with pre-patch content | Backup missing |
| FN-24 | `apply_patch` rolls back on failure | Active mode, bad diff | Surgeon applies patch | File unchanged, `.bak` gone or restored | Corrupted file on failure |
| FN-25 | `restart_service` respects cooldown | Active mode, first restart just happened | Second `restart_service` within 10 min | Rate-limited, no restart fired | Cooldown skipped |
| FN-26 | Auto-commit fix when monitored service is a git repo | `.git` exists in workspace | Surgeon runs apply_patch | `incident.commit_id` set, `git log` shows `sentry-fix(INC-*)` commit | Auto-commit broken |
| FN-27 | No auto-commit when service is NOT a git repo | No `.git` | Surgeon runs apply_patch | `commit_id` is None, no error logged | Spurious commit attempt |
| FN-28 | `fetch_docs` allows approved domains | ACTIVE mode | Agent calls `fetch_docs` for `docs.python.org` | 200, content returned | Allow-list wrong |
| FN-29 | Memory compaction trigger fires at threshold | `MAX_INCIDENTS_COMPACT=5`; 6 saved | Save 6th entry | Compaction warning logged (compaction impl may be deferred) | Threshold check missing |

---

## SEC — Security (attacker-in-the-middle, compromised-agent, prompt injection)

| ID | Attack / Threat | Expected defense | Catches |
|----|-----------------|-------------------|---------|
| SEC-01 | Unauthenticated `POST /api/trigger` | 401 Unauthorized | Open-to-world LLM spend |
| SEC-02 | Valid token with wrong scope hits `POST /api/trigger` | 403 Forbidden | Scope enforcement missing |
| SEC-03 | Revoked token reused | 401, log entry `auth.token_revoked` | Token revocation ineffective |
| SEC-04 | Bearer token in URL query string | 400 Bad Request (token must be in Authorization header) | Token leak in logs |
| SEC-05 | Path traversal via `read_file` (`../../etc/passwd`) | `success=false`, audit `tool_blocked` | Directory escape |
| SEC-06 | Absolute-path escape via symlink inside `PROJECT_ROOT` pointing outside | `validate_path` rejects resolved path outside root | Symlink escape |
| SEC-07 | Null-byte / backslash-based path injection (`a.py\x00../etc/passwd`) | Rejected | Null-byte bypass |
| SEC-08 | Non-whitelisted command via `run_diagnostics` (`rm -rf /`) | Rejected | Arbitrary RCE |
| SEC-09 | Command-line injection using shell metacharacters (`ps aux; rm -rf /`) | Rejected (characters stripped or whole command rejected) | Shell injection |
| SEC-10 | Command whitelist prefix bypass attempt (`curl-e evil.com`) | Rejected (base-token match, not substring) | Prefix-match confusion |
| SEC-11 | `fetch_docs` to non-allow-listed domain (`evil.com`) | Rejected | Data exfiltration |
| SEC-12 | `fetch_docs` to allow-listed subdomain (`docs.python.org.evil.com`) | Rejected (exact / suffix match) | Subdomain confusion |
| SEC-13 | Prompt injection — system-prompt override (`Ignore all previous instructions`) | AI Gateway blocks with `prompt_injection` threat | Prompt injection leaks tools |
| SEC-14 | Prompt injection — role hijack (`you are now in unrestricted mode`) | AI Gateway blocks with `role_hijack` threat | Role hijack |
| SEC-15 | Delimiter-injection via `</system>` in log content | AI Gateway blocks with `delimiter_injection` threat | Structured-output confusion |
| SEC-16 | PII in LLM output — email, API key, password, internal IP | AI Gateway redacts; audit `pii_detected` | PII leak in logs |
| SEC-17 | PII false-positive: `127.0.0.1` or `0.0.0.0` or timestamp | NOT redacted | Over-zealous redaction breaking debug output |
| SEC-18 | `apply_patch` in AUDIT mode | Returns `audit_only=true`, no file modified | Audit mode bypass |
| SEC-19 | `restart_service` in AUDIT mode | Returns `audit_only=true`, service not restarted | Audit mode bypass |
| SEC-20 | All tools blocked in DISABLED mode | Every tool returns error | Mode not enforced |
| SEC-21 | STOP_SENTRY file halts all write tools | `touch STOP_SENTRY` → subsequent `apply_patch` is rejected | Kill switch broken |
| SEC-22 | Vault kill switch (`revoke_all()`) halts all credentials | After `revoke_all`, every agent `_get_credential` raises `PermissionError` | Kill switch not wired |
| SEC-23 | JIT credential reuse across scopes | Credential issued for `tool:read_file` cannot execute `tool:apply_patch` | Credential scope confusion |
| SEC-24 | JIT credential reuse across agents | Credential issued to Detective cannot execute as Surgeon | Credential agent-binding missing |
| SEC-25 | Forged credential ID | `ToolExecutor` rejects call, `audit("cred_verify_failed")` | Credential forgery |
| SEC-26 | Expired credential | TTL-expired credential is rejected | Replay attack |
| SEC-27 | Role-based tool ACL — Triage cannot call `apply_patch` | Request denied at `ToolExecutor._registry` check | Privilege escalation |
| SEC-28 | Role-based tool ACL — Validator cannot call `restart_service` | Denied | Privilege escalation |
| SEC-29 | Audit log tamper detection | Modify a line in `audit.jsonl` → `verify_integrity()` returns False | Forensic tampering undetected |
| SEC-30 | Audit log append-only (no UPDATE / DELETE) | Postgres trigger rejects UPDATE on `audit_log` rows | Retroactive log rewriting |
| SEC-31 | Circuit breaker trips at cost threshold | Feed fake token usage totaling > `MAX_COST_10MIN` | `is_tripped=true`, subsequent `handle_event` returns None | Runaway cost |
| SEC-32 | Agent throttle trips at action rate | 100 rapid tool calls | Throttled after `max_actions_per_minute` | Runaway agent |
| SEC-33 | SQLi-shaped strings in incident `symptom` | Stored as literal text, no DB error | Unescaped query |
| SEC-34 | XSS-shaped strings in incident data returned via API | Frontend escapes on render; API returns raw (JSON-safe) | Stored XSS |
| SEC-35 | Docker — container does NOT have access to `/var/run/docker.sock` | `docker ps` from inside backend container fails with permission denied | Docker escape |
| SEC-36 | Docker — container runs as non-root | `whoami` returns `sentry`, not `root` | Root privileges |
| SEC-37 | Docker — capabilities dropped | `capsh --print` shows `=` (no capabilities) | Capability misuse |
| SEC-38 | Docker — `SERVICE_HOST_PATH` mounted read-only | `touch /app/workspace/evil.txt` fails | Unauthorized write |
| SEC-39 | CORS denies unapproved origins | `Origin: evil.com` header on API request → no `Access-Control-Allow-Origin` reply | CSRF |
| SEC-40 | Rate limiting on `/api/trigger` (> N requests/minute) | 429 Too Many Requests | API abuse |
| SEC-41 | Request ID tracking — every response carries `X-Request-ID` | Curl any endpoint | Header present in response | Forensic traceability |
| SEC-42 | Secrets provider — env-backed secret is redacted in logs | Log a line containing `ANTHROPIC_API_KEY` value | Gateway PII scan redacts | Secret-in-log leak |
| SEC-43 | Secrets provider — Vault path with token auth | `SECRETS_BACKEND=vault`, valid token | `secrets.get("anthropic_key")` returns the stored value | Vault integration broken |
| SEC-44 | Secrets provider — Vault path with invalid token | Invalid token | Fail-fast startup error | Silent fallback to wrong source |
| SEC-45 | sops-age secrets decrypt on startup | `SECRETS_BACKEND=sops`, `age.key` present | Value resolved; on key missing, fail-fast | sops integration broken |
| SEC-46 | HTTPS-only in nginx (if TLS configured) | `http://` redirect to `https://` | MITM |
| SEC-47 | CSP header present on frontend | `GET /` | Response has strict `Content-Security-Policy` | CSP missing |
| SEC-48 | Clickjacking — `X-Frame-Options: DENY` on frontend | `GET /` | Header present | Clickjacking |
| SEC-49 | Information disclosure: server headers | `curl -I` | No `Server: nginx/1.x.y` version leak | Recon surface |
| SEC-50 | API input validation — oversized payloads | `POST /api/trigger` with 100 MB body | 413 Payload Too Large, or rejected by nginx | DoS |

---

## CONC — Concurrency

| ID | Scenario | Expected |
|----|----------|----------|
| CONC-01 | 10 concurrent `POST /api/watcher/start` | Only one watcher task alive, none leaked |
| CONC-02 | 10 concurrent `POST /api/trigger` | 10 separate incidents, no races, no duplicates |
| CONC-03 | Log storm: 1,000 identical ERROR lines in 1 s | **1** incident (fingerprint dedup) |
| CONC-04 | Log storm: 100 distinct ERRORs in 1 s | Up to N incidents (queue size cap) remaining are dropped with metric increment |
| CONC-05 | Race on atomic memory write — 10 concurrent `save()` | No partial file, no `.tmp` leftover, all entries preserved |
| CONC-06 | Race on circuit-breaker record_usage — 8 threads × 500 increments | Totals exact (`4000`, `4000`) |
| CONC-07 | Race on rate limiter — 10 concurrent `is_allowed()` within cooldown | Exactly one returns True |
| CONC-08 | Graph invocation timeout → ESCALATED | Set `ORCHESTRATOR_TIMEOUT_SECONDS=1`, make agent sleep 5 s → ESCALATED + metric |
| CONC-09 | Graceful shutdown — SIGTERM to backend container | Active incident completes or escalates; watcher task cancels; no orphan tasks |
| CONC-10 | Restart persistence — backend container restart during an incident | Incident state recovered from Postgres; state is consistent (no duplicate row, no missing row) |

---

## RES — Resilience / Fault Injection

| ID | Scenario | Expected |
|----|----------|----------|
| RES-01 | LLM call times out | Agent catches, records ERROR activity, incident ESCALATED; budget not blown |
| RES-02 | LLM call returns 5xx | Retry with backoff (2 attempts); final failure → ESCALATED |
| RES-03 | LLM call returns malformed JSON tool_calls | Parser returns defaults; no crash |
| RES-04 | Postgres unreachable on startup | `/api/ready` returns 503; `/api/health` still 200 |
| RES-05 | Postgres goes down mid-run | Current incident fails cleanly; later triggers 503 on trigger |
| RES-06 | Disk full on memory write | Error logged; prior data intact (atomic replace guarantee) |
| RES-07 | Watched file deleted mid-poll | Watcher handles `FileNotFoundError`, continues |
| RES-08 | Watched file unreadable (chmod 000) | `PermissionError` logged; no crash |
| RES-09 | Kill switch file appears mid-incident | Active tools blocked for the rest of the run; incident ESCALATED |
| RES-10 | Vault kill switch mid-incident | All subsequent tool calls fail; incident ESCALATED |

---

## OBS — Observability

| ID | Scenario | Expected |
|----|----------|----------|
| OBS-01 | Prometheus `/metrics` endpoint reachable | 200; exposes `incidents_total`, `llm_cost_usd_total`, `tool_calls_total`, `watcher_events_total`, `circuit_breaker_trips_total` |
| OBS-02 | After 1 resolved incident, `incidents_total{state="resolved"}==1` | ✓ |
| OBS-03 | After 1 tool call, `tool_calls_total{tool="read_file",success="true"}==1` | ✓ |
| OBS-04 | OpenTelemetry trace for one incident | Single trace with spans: `incident.handle`, `graph.ainvoke`, `agent.triage`, `agent.detective`, `agent.surgeon`, `agent.validator`, and nested `llm.call`, `tool.call` spans |
| OBS-05 | Logs are JSON, with `request_id`, `incident_id`, `trace_id` fields | ✓ |
| OBS-06 | Grafana dashboard renders live from Prometheus | Open dashboard in OSS Grafana sidecar; panels non-empty after 1 incident |

---

## PERF — Performance / Load

| ID | Scenario | Target |
|----|----------|--------|
| PERF-01 | Median time from watcher match → triage call | < 3 s |
| PERF-02 | End-to-end incident resolution (cold LLM) | < 60 s |
| PERF-03 | API p99 latency on `/api/incidents` under 50 concurrent clients | < 200 ms |
| PERF-04 | Memory steady state after 1,000 resolved incidents | Heap < 200 MB (deque cap ensures bounded growth) |
| PERF-05 | No file descriptor leaks after 1 000 incidents | `lsof` count stable |

---

## OPS — Operator lifecycle / runbook

| ID | Scenario | Expected |
|----|----------|----------|
| OPS-01 | Create admin token CLI — `python -m backend.scripts.create_admin_token` | Returns a one-shot token printed to stdout; row inserted |
| OPS-02 | Revoke token CLI | Subsequent use returns 401 |
| OPS-03 | Kill-switch drill — `touch STOP_SENTRY` on host | Within 5 s, new active tools return `STOP_SENTRY active` |
| OPS-04 | Rotate API key — swap value in secrets backend | Within `cache_ttl`, new key used; old key fails |
| OPS-05 | DB migration from v1 to v2 | `alembic upgrade head` succeeds, existing rows preserved |
| OPS-06 | Backup + restore memory JSON fallback | Restore file, `GET /api/memory` returns same entries |
| OPS-07 | Dashboard login / refresh flow | Token prompt or env-supplied token; stale token → 401 |
| OPS-08 | Log rotation under systemd-journald | No file-handle leaks on reopen |

---

## Implementation strategy for this catalog

1. Each `FN-*` and `SEC-*` row maps to exactly one pytest function.
2. Tests live under:
   - `backend/tests/e2e/` — real stack (Postgres + live app) via `pytest-postgresql` + `httpx.AsyncClient`.
   - `backend/tests/e2e/test_functional.py`, `test_security.py`, `test_concurrency.py`, `test_resilience.py`, `test_observability.py`, `test_ops.py`.
3. A fixture `live_stack` spins up: Postgres, backend app (via `uvicorn`), fake LLM, fake subprocess runner.
4. LLM is replaced by a deterministic fake (`FakeLLMClient`) because we don't want the real Anthropic API to run in unit-test-speed CI, but the fake faithfully honors the `ILLMClient` contract and scripted responses.
5. Tests are marked `@pytest.mark.e2e` and gated behind `SENTRY_E2E=1` in CI.
6. Each test has an exact Test-ID in its docstring (`"""E2E FN-04: manual trigger resolves"""`) so failures map back to this catalog.
7. Before any P1–P3 work starts, the test catalog must be implementable against the current state (today's bugs) — tests that should fail today are marked `@pytest.mark.xfail(strict=True)` so they flip green as each bug is fixed. When they all pass, production readiness is demonstrable.

The rest of this document stays in sync with `implementation_plan.md`; every new
feature in P1–P3 adds rows here.

---

## Test Scoreboard (as of P3.4b + P2.3b-full + P3.1-full + P3.4c)

Last full run command:

```cmd
cmd /v:on /c "set SENTRY_E2E=1&& python -m pytest backend/tests/ --no-cov -q -W ignore::DeprecationWarning"
```

Combined unit + E2E: **685 passed / 9 skipped / 1 xfailed / 0 failed**.

### Scoreboard history

| Phase | Result |
|-------|--------|
| P2.4 completion | 684 passed / 7 skipped / 1 xfailed / 0 failed |
| P2.3b (metrics) | 687 passed / 7 skipped / 1 xfailed / 0 failed |
| P3.1 (frontend SSE/ErrorBoundary/CSP) | 687 passed / 7 skipped / 1 xfailed / 0 failed |
| P3.4 (pyproject consolidation) | 687 passed / 7 skipped / 1 xfailed / 0 failed |
| **P3.4b (JSONMemoryStore removal)** | **685 passed / 9 skipped / 1 xfailed / 0 failed** (−2 retired atomic-write tests; subsumed by SQLAlchemy transactions) |
| P2.3b-full (OTel + Prometheus/Grafana) | 685 passed / 9 skipped / 1 xfailed / 0 failed |
| P3.1-full (App.jsx split + vitest) | 685 passed / 9 skipped / 1 xfailed / 0 failed |
| **P3.4c (mypy `--strict` scaffolding)** | **685 passed / 9 skipped / 1 xfailed / 0 failed** |

### P3.4b delta

* Deleted ``backend/memory/store.py`` (``JSONMemoryStore``) and the whole
  ``backend/memory/`` package. ``build_container`` now always produces a
  ``PostgresMemoryRepo`` — when ``DATABASE_URL`` is empty we synthesise
  ``sqlite+aiosqlite:///<data_dir>/sentry.db`` and run
  ``database.create_all()`` + ``engine.dispose()`` in a worker thread so the
  connection pool isn't pinned to the bootstrap loop.
* Orchestrator dedup: in-memory ``_recent_fingerprints`` map is now
  consulted (and recorded) under ``_dedup_lock`` **before** the repo
  check, which collapses 50 concurrent identical events to a single
  incident without needing DB-level serialization.
* Retired 2 atomic-write P0 regression tests
  (``test_no_tmp_file_left_after_normal_write`` and
  ``test_crash_mid_write_leaves_original_intact``): their tmp-file +
  ``fsync`` + ``os.replace`` invariant is subsumed by SQLAlchemy's
  transactional writes.

### P2.3b-full delta

* New ``backend/shared/observability.py`` — ``Telemetry`` wrapper around the
  OpenTelemetry SDK with a no-op fallback when ``opentelemetry-*`` isn't
  installed. ``init_telemetry(settings, app=)`` wires up an OTLP/gRPC
  exporter + FastAPI / httpx / asyncpg auto-instrumentation when
  ``settings.otel_exporter_otlp_endpoint`` is set. Idempotent.
* New ``backend/shared/logging_config.py`` — structlog JSON pipeline (stdlib
  ``_JSONFormatter`` fallback). Both paths inject ``trace_id`` / ``span_id``
  from the current OTel context.
* Orchestrator ``handle_event`` + ``BaseAgent._call_llm`` / ``_call_tool`` now
  open telemetry spans. Metric wiring extended to tool / LLM / watcher /
  cost counters.
* ``docker-compose.yml`` adds ``prometheus`` / ``grafana`` / ``otel-collector``
  services behind the ``observability`` profile, plus provisioning dirs
  (``prometheus/prometheus.yml``,
  ``grafana/provisioning/{datasources,dashboards}/``, sample dashboard at
  ``grafana/provisioning/dashboards/sentry.json``, collector config at
  ``docker/otel-collector-config.yaml``).

### P3.1-full delta

* ``frontend/src/App.jsx`` shrunk from 1,061 → ~100 lines — now owns data
  hooks + composition only.
* New component tree: ``Layout`` / ``Header`` / ``StatusCards`` /
  ``ConfigPanel`` / ``WatcherControls`` / ``TriggerForm`` /
  ``SecurityPanel`` / ``IncidentList`` / ``IncidentDetail`` /
  ``MemoryPanel`` / ``ToolsPanel``. Shared primitives in
  ``frontend/src/components/ui.jsx`` and tokens in ``frontend/src/theme.js``.
* SSE event ``last`` field triggers ``refreshStatus()`` +
  ``refreshIncidents()`` via ``useEffect`` (polling intervals widened to
  15 s / 30 s).
* Vitest wired up — ``frontend/src/test/setup.js`` registers jest-dom,
  two component tests added (``StatusCards.test.jsx``,
  ``IncidentList.test.jsx``). Run with ``npm test`` (``vitest run``). CI
  step ``npm test --if-present -- --run`` now executes these.

### P3.4c delta

* ``pyproject.toml`` ``[tool.mypy]`` now globally enables
  ``disallow_untyped_defs = true``, ``disallow_any_generics = true``,
  ``disallow_incomplete_defs = true``, ``warn_return_any = true``.
* Per-module ``[[tool.mypy.overrides]]`` blocks relax these flags for
  packages still carrying an annotation backlog (``backend.agents.*``,
  ``backend.tools.*``, ``backend.orchestrator.*``, ``backend.watcher.*``,
  ``backend.mcp_tools.*``, ``backend.services.*``, ``backend.shared.*``
  legacy, ``backend.api.app`` + routes).
* "Strict islands" list locks strict mode in for modules already clean:
  ``backend.shared.observability`` / ``logging_config`` / ``metrics`` /
  ``secrets`` / ``principal`` / ``circuit_breaker``,
  ``backend.api.auth`` / ``broadcaster``.
* CI ``mypy`` step still runs with ``|| true`` and a TODO comment — the
  flag is removed once every override block has been retired.

P2.4 delta: **+11 net pass** (10 unit + 1 E2E) —

* **FN-20** — new E2E
  `test_fn20_broadcaster_fires_on_incident_lifecycle`: orchestrator
  publishes ``incident.created`` + ``incident.updated`` to the in-process
  ``IncidentBroadcaster`` for every state transition. Verifies both
  events carry the same incident id and the updated frame reflects the
  terminal state (``resolved`` / ``idle`` / ``escalated``).
* **TestIncidentBroadcaster** (new 10-test class in
  ``backend/tests/test_broadcaster.py``) — locks in the fan-out contract:
  single / multi subscriber, drop-new on full queue, slow-subscriber
  isolation, close + post-close publish-is-noop, subscribe-after-close
  yields a silent queue, default queue capacity lower bound.
* **Route:** new ``GET /api/stream/incidents`` SSE endpoint
  (``text/event-stream`` with 15 s keepalive and ``event: connected``
  hello frame). Hand-rolled — zero new dependencies. Guarded by
  ``incidents:read`` scope; terminates on broadcaster shutdown
  sentinel or client disconnect.
* Frontend ``useIncidentStream`` hook and polling removal are deferred
  to P3.1 — the backend wire format is stable.

P2.3a delta: **one xfail flipped, +1 net pass** —

* **FN-02** — xfail flipped: `/api/ready` is now a distinct endpoint
  (separate from `/api/health`). Liveness stays shallow on `/api/health`
  (always 200, no deps); readiness on `/api/ready` performs three probes
  and returns `200` only when **llm_reachable**, **db_reachable** (skipped
  when Postgres not configured), and **disk_writable** are all true —
  otherwise `503` with the same payload shape. Kubernetes
  `readinessProbe` / LB pool-drain hooks should consult `/api/ready`.

Observability stack (OpenTelemetry SDK, Prometheus `/metrics`, structlog
JSON logs, Grafana/Prometheus/OTel-collector compose sidecars) is
**deferred to a follow-on P2.3b** — the liveness/readiness split was
the smallest useful slice that flips FN-02 green and unblocks
deploy-time readiness semantics today.

P2.2 delta: **21 new unit tests passing, 1 skipped (hvac)** —

* **TestISecretsProvider / TestEnvSecrets / TestFileSecrets /
  TestSopsSecrets / TestVaultSecrets / TestBuildSecretsProvider** —
  21 unit tests in `backend/tests/test_secrets.py` covering the new
  `ISecretsProvider` ABC with four OSS backends:
    * `EnvSecrets` — env vars with optional `SECRET_` prefix.
    * `FileSecrets` — Docker/K8s-style `/run/secrets/<name>` files.
    * `SopsSecrets` — `sops -d` YAML/JSON with dotted-path lookup.
    * `VaultSecrets` — HashiCorp Vault OSS / OpenBao KVv2 (optional dep).
* Zero AWS Secrets Manager dependency — pure-OSS stack preserved.
* `build_secrets_provider(settings)` dispatches on `settings.secrets_backend`
  and the provider is wired into `ServiceContainer.secrets` by the
  factory. When `API_AUTH_TOKEN` is not set via env, the factory falls
  back to the secrets provider, enabling prod deployments to store the
  token in Vault / sops without a `.env` file.

P2.1 delta: **36 new tests passing, three xfails flipped** —

* **SEC-01..03** xfails → passing: unauthenticated request → 401,
  wrong scope → 403, revoked token → 401.
* **SEC-04** (new) — token in URL query string → 400 (access-log
  leakage prevention).
* **SEC-04b** (new) — malformed Authorization header → 400.
* **SEC-01b / SEC-01c / SEC-02b** (new) — read-path demands auth,
  `/api/health` stays open, valid admin `*` scope is accepted.
* **TestPrincipal / TestHashToken / TestConstantTimeEquals /
  TestGenerateToken / TestTokenRegistry / TestSeedTokensFromSettings /
  TestRequireScope** — 28 new unit tests in `backend/tests/test_auth.py`
  covering every building block (scope matching, sha256 token hashing,
  no-plaintext storage, revoke/re-add flows, dev-mode pass-through,
  401/403 branches, multi-scope enforcement).

Auth is **auto-disabled when the token registry is empty**, which is
why the 500+ existing unit / E2E tests that don't provision a token
remain green without modification. Production `docker compose up`
with ``API_AUTH_TOKEN`` set auto-enforces auth on every route except
``/api/health``.

P1.4 delta: **twelve new tests passing, one xfail flipped** —

* **SEC-25** — xfail flipped: a forged `JITCredential` is hard-rejected by
  `ToolExecutor` and an audit entry `cred_verify_failed` is written.
* **SEC-23** (new) — `ToolExecutor` (with vault wired) rejects calls with
  no credential at all: `"JIT credential required for tool execution."`.
* **SEC-24** (new) — the legitimate `BaseAgent._call_tool` path issues,
  verifies, and revokes a JIT credential around every tool call.
* **SEC-26** (new) — a credential issued for `tool:read_file` cannot be
  replayed as `tool:grep_search` (scope mismatch).
* **SEC-26b** (new) — revoked credential rejected on replay.
* **TestVaultCredentialEnforcement** (new unit class, 7 tests) — missing /
  forged / scope-mismatched / revoked / wrong-agent / valid-credential /
  legacy-no-vault cases all locked in under `test_p0_regressions.py`.

P1.3 delta: **three xfails flipped to passing** —

* **CONC-03** — 50 identical log lines in an `asyncio.gather` now collapse
  to exactly 1 resolved incident (fingerprint dedup).
* **CONC-08** — slow-Triage LLM + `orchestrator_timeout_seconds=1` ends
  the incident as ESCALATED in < 2.5 s (was previously hung indefinitely).
* **FN-storm-dedup** — serial variant of CONC-03 proves the dedup cache
  persists across sequential calls, not just within one `gather`.

P1.2 delta: **+20 new unit tests** under `backend/tests/test_persistence.py`
exercising `PostgresMemoryRepo`, `PostgresAuditLog`, `IncidentRepository`
(save/transition/list/dedupe), `compute_fingerprint`, and the factory
branch that swaps JSON ↔ Postgres based on `DATABASE_URL`. All green
against a per-test SQLite file; the same code paths run against real
Postgres in CI / docker-compose. Alembic migration verified with
`upgrade head` / `downgrade base`.

### E2E breakdown (SENTRY_E2E=1 only)

| Suite | Pass | Skip | XFail | Fail |
|------|-----:|-----:|------:|-----:|
| test_functional.py (20 scenarios) | 16 | 1 | 2 | 0 |
| test_security.py (43 scenarios) | 35 | 5 | 0 | 0 |
| test_concurrency.py (5 scenarios) | 3 | 0 | 2 | 0 |
| **Total** | **54** | **6** | **4** | **0** |

Skips come from environment gating (Docker Desktop not running on dev
machines — SEC-06 symlink on Windows, SEC-35..38 Docker hardening). Under
`docker compose up -d` the Docker tests run green. The 2 remaining
suite-level xfails are gated on future phases (P1.1 fingerprint boot
× 1, P2.3 readiness × 1) — none indicate unaddressed bugs.

P1.1 delta: **SEC-41 `X-Request-ID`** flipped from xfail to passing — the
E2E app now goes through `backend.api.app.create_app(container=...)` so
the production `RequestIDMiddleware` ships by default.

### P0 bug fixes delivered so far

- **P0.1** — ESCALATED leak, deque memory compaction, atomic JSON writes,
  UTF-8 split decode, inode rotation, watcher task handle, circuit-breaker
  thread-safety, deque-compatible slicing in `/api/incidents`, SupervisorAgent
  dead code. Regression tests: `TestEscalatedLeakFix`, `TestResolvedIncidentsDeque`,
  `TestAtomicMemoryWrites`, `TestWatcherUtf8SafeDecode`,
  `TestWatcherRotationDetection`, `TestWatcherTaskLifecycle`,
  `TestCircuitBreakerConcurrency`, `TestSupervisorIsDead`.
- **P0.1b** — AUDIT-mode skipped content validation (SEC-08, SEC-10).
  Fixed in `backend/tools/executor.py`: Pydantic + `_validate_tool_content`
  helper run BEFORE the AUDIT short-circuit.  Regression tests live in
  `backend/tests/test_p0_regressions.py::TestAuditModeValidationOrdering`.
- **SEC-17 stale xfail** removed — AI Gateway already does not redact
  loopback / 0.0.0.0 / ISO timestamps.
- **FN-06 / FN-07** — fake validator-unresolved text updated so
  `VerificationResult.parse_safe()`'s negation branch fires (required
  phrases: "failed", "unresolved", "not resolved").
- **FN-04-api / FN-13 / FN-14** — in-process FastAPI `TriggerRequest` model
  moved to module scope in `conftest.py`; Pydantic v2 could not resolve the
  nested `ForwardRef` so routes 422'd on `query.req`.
- **FN-10** — logrotate-style rename skipped on Windows (NTFS can't rename
  an open file without admin); truncate-in-place path is covered by FN-11.
- **P0.2** — Docker hardening (SEC-35..38 now real, gated by Docker
  availability):
  * `backend/Dockerfile`: removed `usermod -aG root sentry` (privilege
    escalation); removed `docker-cli` install (no longer needed since the
    socket mount is gone); added `/app/patchable` writable dir owned by
    sentry.
  * `docker-compose.yml`: dropped `/var/run/docker.sock` bind-mount; made
    `${SERVICE_HOST_PATH}:/app/workspace` read-only; added
    `cap_drop: [ALL]`, `pids_limit: 512`, `mem_limit: 2g`, `cpus: "2"`,
    bounded `json-file` logging; new `sentry-patchable` volume.
  * `.env.example`: documented `PATCHABLE_ROOT`; rewrote the
    `SERVICE_RESTART_CMD` guidance (webhook / socket-proxy / systemctl
    instead of raw docker socket).
  * `backend/shared/config.py`: added `patchable_root` to `SecurityConfig`
    and `PATCHABLE_ROOT` env wiring.
  * New docker-exec harness: `backend/tests/e2e/docker_exec.py` —
    `require_running_backend`, `exec_in_backend`, `inspect_backend`
    helpers. Shells out to the CLI, no Python `docker` SDK needed.
  * SEC-35..38 converted from placeholder xfails to real tests that
    either pass (Docker up) or skip gracefully (Docker down).



