# Sentry Operator Runbook

This runbook covers the day-to-day operations of a running Sentry
deployment. It assumes the stack has been deployed via the
`docker-compose.yml` in the repository root.

- [1. First-time setup](#1-first-time-setup)
- [2. Day-to-day monitoring](#2-day-to-day-monitoring)
- [3. Incident triage](#3-incident-triage)
- [4. Kill-switch drill](#4-kill-switch-drill)
- [5. Reset the cost circuit breaker](#5-reset-the-cost-circuit-breaker)
- [6. Rotate secrets](#6-rotate-secrets)
- [7. Back up / restore state](#7-back-up--restore-state)
- [8. Upgrades and DB migrations](#8-upgrades-and-db-migrations)
- [9. Disaster recovery](#9-disaster-recovery)

---

## 1. First-time setup

```bash
cp .env.example .env
# Edit .env: at minimum set ANTHROPIC_API_KEY / BEDROCK_*, API_AUTH_TOKEN,
# SERVICE_HOST_PATH, DATABASE_URL.

docker compose up -d
docker compose exec backend alembic -c backend/persistence/alembic.ini upgrade head

# Sanity checks:
curl -fsS http://localhost:8000/api/health                                  # 200 ok
curl -fsS -H "Authorization: Bearer $API_AUTH_TOKEN" \
     http://localhost:8000/api/ready                                        # 200 ready
curl -fsS http://localhost:8000/metrics | head -20                          # Prometheus text
```

If `/api/ready` returns 503, inspect the JSON body — it reports which
of `llm_reachable` / `db_reachable` / `disk_writable` failed and the
underlying error message.

---

## 2. Day-to-day monitoring

**Dashboard** — `http://localhost:3000`. The frontend uses the SSE
feed (`/api/stream/incidents`, P2.4) to show live state transitions.

**Prometheus metrics** — scrape `http://sentry-backend:8000/metrics`.

Useful alerts:

| Rule                                                              | Severity |
|-------------------------------------------------------------------|----------|
| `increase(sentry_circuit_breaker_trips_total[10m]) > 0`           | page     |
| `increase(sentry_incidents_total{state="escalated"}[1h]) > 5`     | warn     |
| `rate(sentry_llm_cost_usd_total[10m]) * 600 > MAX_COST_PER_10MIN` | warn     |
| `up{job="sentry-backend"} == 0`                                   | page     |

---

## 3. Incident triage

When Sentry reports an incident as ESCALATED:

```bash
# List active + recent incidents
curl -H "Authorization: Bearer $API_AUTH_TOKEN" \
     http://localhost:8000/api/incidents | jq

# Fetch full activity log for one incident (every LLM call, tool call,
# decision, and phase transition — this is the canonical forensic trail).
curl -H "Authorization: Bearer $API_AUTH_TOKEN" \
     http://localhost:8000/api/incidents/INC-20260422-013200-ab12cd | jq

# Verify the audit log hasn't been tampered with.
# (JSON mode — the ImmutableAuditLog.verify_integrity() helper.)
docker compose exec backend python -m backend.scripts.verify_audit_log
```

Escalation triggers (covered by FN-06..FN-07):

* `retry_count >= settings.security.max_retries` — validator returned
  "unresolved" too many times.
* `asyncio.TimeoutError` in `Orchestrator.handle_event` — a single
  incident exceeded `ORCHESTRATOR_TIMEOUT_SECONDS` (default 300).

After rootcausing, consider tightening the watcher pattern or adding
a memory-entry by hand so Sentry sees the class of error as already
known.

---

## 4. Kill-switch drill

There are two kill switches; both are documented in `ops/SECURITY.md`.

### 4.1 Host-level `STOP_SENTRY` file

```bash
# From the host — no container restart needed.
touch /path/to/mounted/STOP_SENTRY

# Verify: every subsequent active-tool call returns
# "STOP_SENTRY active — write tools disabled".
curl -H "Authorization: Bearer $API_AUTH_TOKEN" \
     -X POST http://localhost:8000/api/trigger \
     -d '{"message": "ERROR: kill-switch drill"}'

# Clear when done.
rm /path/to/mounted/STOP_SENTRY
```

### 4.2 In-process vault kill (emergency)

```bash
docker compose exec backend python -c \
  "from backend.shared.factory import build_container; \
   from backend.shared.settings import get_settings; \
   c = build_container(get_settings()); c.vault.revoke_all(); \
   print('vault killed')"
# This is for break-glass use; every subsequent tool call will fail.
```

---

## 5. Reset the cost circuit breaker

```bash
curl -H "Authorization: Bearer $API_AUTH_TOKEN" \
     http://localhost:8000/api/security | jq '.circuit_breaker'
# If "tripped": true and the 10-minute window has NOT expired, restart
# the backend or wait:
docker compose restart backend
```

Prometheus gives you the history: `sentry_circuit_breaker_trips_total`.

---

## 6. Rotate secrets

Sentry reads secrets at startup from the backend picked by
`SECRETS_BACKEND`. To rotate:

### Vault / OpenBao (`SECRETS_BACKEND=vault`)

```bash
bao kv put secret/sentry/anthropic_key value=$NEW_KEY
bao kv put secret/sentry/api_auth_token value=$NEW_TOKEN
docker compose restart backend
```

### sops-age (`SECRETS_BACKEND=sops`)

```bash
sops secrets.yaml          # edit in place
sops updatekeys secrets.yaml  # after adding a new recipient
docker compose restart backend
```

### File secrets (`SECRETS_BACKEND=file`)

```bash
printf '%s' "$NEW_TOKEN" > /run/secrets/api_auth_token
docker compose restart backend
```

### Dev env var (`SECRETS_BACKEND=env`) — **not for production**

Edit `.env`, `docker compose up -d`.

---

## 7. Back up / restore state

### Postgres mode

```bash
# Backup:
docker compose exec postgres pg_dump -U sentry sentry > backup-$(date +%F).sql

# Restore:
docker compose exec -T postgres psql -U sentry sentry < backup-2026-04-22.sql
```

### JSON mode (no DATABASE_URL)

```bash
# Back up both the memory file and the audit log.
docker compose cp backend:/app/data/memory.json memory-$(date +%F).json
docker compose cp backend:/app/data/audit.jsonl audit-$(date +%F).jsonl
```

---

## 8. Upgrades and DB migrations

```bash
git pull
docker compose pull                                              # latest images
docker compose exec backend alembic -c backend/persistence/alembic.ini upgrade head
docker compose up -d --build backend frontend
curl -fsS http://localhost:8000/api/ready                        # confirm deps
```

Roll back:

```bash
docker compose exec backend alembic -c backend/persistence/alembic.ini downgrade -1
docker tag ghcr.io/your-org/sentry-backend:<previous> sentry-backend:current
docker compose up -d --force-recreate backend
```

---

## 9. Disaster recovery

If the backend container is in a crash loop:

1. `docker compose logs backend --tail=200` — look for the startup
   exception. Most common: `/api/ready` failing because the DB migration
   didn't run (Postgres mode) or the secrets backend is unreachable.
2. If secrets: `docker compose logs openbao` / inspect the sops file.
3. If DB: `docker compose exec postgres psql -U sentry sentry -c '\dt'`.
4. If all else fails, flip to JSON mode by setting `DATABASE_URL=""` in
   `.env` and restarting — the memory store uses file persistence and
   the orchestrator's P1.3 dedup falls back to an in-memory cache.

The audit log is append-only and the hash chain allows you to verify
history after a restore: see `ImmutableAuditLog.verify_integrity()`.
