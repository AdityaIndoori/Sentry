# Sentry as a multi-tenant SaaS

This document describes the SaaS layer that lets multiple users sign up,
log in, connect their own services, and have Sentry triage/heal incidents
scoped to their own account.

## The seamless onboarding flow (target UX)

1. **Land → Sign up.** A visitor opens the app, clicks **Sign up**, enters
   email + password. An account is created instantly and a session token
   is returned + stored by the SPA. (No email-verification gate on the
   first cut — that's noted as future work.)
2. **Empty dashboard with one CTA.** The dashboard renders with a
   prominent **🔌 Connect a service** panel at the top.
3. **Connect a service.** The user types a service name (e.g. `prod-api`)
   and clicks **Generate token**. They immediately get:
   - a one-time **ingestion token** (`sing_…`), and
   - a copy-paste **`curl` one-liner** pre-filled with that token.
   They drop the token into their log shipper (curl, a cron, Vector/Fluent
   Bit HTTP sink, a Docker sidecar — anything that can POST JSON).
4. **Logs flow → incidents appear.** As soon as a log line matching an
   error pattern arrives at `POST /api/ingest`, Sentry spins up an
   incident **tagged with that account** and runs the
   Triage → Detective → Surgeon → Validator pipeline. The incident shows
   up live on the dashboard via the existing SSE stream.
5. **Audit by default.** New accounts default to `audit` mode — Sentry
   observes + recommends but doesn't execute fixes until the user opts in.

## What was built

### Data model (multi-tenancy)

| Table | Purpose |
|-------|---------|
| `accounts` | One row per signed-up user. `email` (unique), PBKDF2 `password_hash`, `default_mode`. |
| `ingestion_tokens` | Per-account log-shipping keys. Only the SHA-256 hash is stored; the raw `sing_…` token is shown once at mint time. |
| `incidents.account_id` | **New nullable column.** Tags every incident with its owning tenant. `NULL` = global/single-tenant (preserves the pre-SaaS + local-dev behaviour). |

Migration: `backend/persistence/migrations/versions/20260616_0002_saas_multitenancy.py`.
On SQLite/dev the tables are auto-created by `Database.create_all()`.

### Identity & auth (reuses the existing rails)

Sentry already had an opaque-bearer-token system (`TokenRegistry`,
`Principal`, `AuthMiddleware`, `require_scope`). The SaaS layer reuses it
rather than introducing JWT:

- **Signup/login mint a session token** (`sess_…`) registered in the live
  `TokenRegistry` and bound to a `Principal` whose new `account_id` field
  is the account id.
- The existing `AuthMiddleware` validates the bearer on every request and
  attaches the `Principal`; `require_scope` continues to gate the operator
  endpoints unchanged.
- **Tenant scoping** rides on `Principal.account_id`: incidents created via
  ingestion are saved with that `account_id`; the incident repo's `save`
  accepts an `account_id` keyword.

Password hashing is stdlib `hashlib.pbkdf2_hmac` (600k iterations,
self-describing `pbkdf2_sha256$iters$salt$hash` format) — no new deps.

### Cloudflare Access (hosted SSO)

For the hosted deployment, password management is offloaded to
**Cloudflare Access** (Zero Trust). When `CF_ACCESS_TEAM_DOMAIN` and
`CF_ACCESS_AUD` are both set, the auth layer switches mode:

- Cloudflare Access authenticates the browser at the edge and injects a
  signed `Cf-Access-Jwt-Assertion` header on every request to the origin.
- `backend/api/cf_access.py` (`CloudflareAccessVerifier`) fetches the
  team's JWKS from `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`,
  verifies the RS256 signature + `aud` + issuer, and reads the verified
  `email` claim. (We never trust Cloudflare's plaintext email header — only
  the cryptographically verified JWT.)
- `AuthMiddleware` checks the CF Access header **before** the bearer path.
  A valid JWT calls `AccountRepository.get_or_create_sso(email)` to
  auto-provision the tenant account (passwordless — the stored
  `password_hash` is a sentinel that never verifies, so the password-login
  endpoint can't be used for an SSO account), then attaches a tenant-scoped
  `Principal`. The resolved principal is cached on the container so
  subsequent requests skip the DB.
- `GET /api/auth/config` tells the SPA which mode is active
  (`{"mode": "cloudflare_access" | "password", "cf_access_enabled": bool,
  "logout_url": str}`). In CF Access mode the frontend skips its password
  screen entirely and routes "Log out" to the Access `/cdn-cgi/access/logout`
  endpoint.

The verifier depends on `pyjwt[crypto]` (added to
`backend/requirements.txt`). It is import-safe without PyJWT — on a dev box
that doesn't install it, the verifier reports "unavailable" and the auth
layer falls back to the password flow. Setting neither env var keeps the
built-in email+password flow, so local dev and the existing test suite are
unaffected.

> **Access policy note:** `/api/ingest` must be a PUBLIC (bypass) path in
> the Access application so customer log shippers can POST with their
> `X-Ingest-Token` header (they have no browser session). Everything else
> sits behind Access.

### API surface (`backend/api/saas_routes.py`)

| Method & path | Auth | Purpose |
|---------------|------|---------|
| `POST /api/auth/signup` | open | Create account, return session token. |
| `POST /api/auth/login` | open | Verify creds, return session token. |
| `GET /api/auth/me` | bearer | Current account/principal. |
| `GET /api/ingest-tokens` | bearer | List this tenant's ingestion tokens. |
| `POST /api/ingest-tokens` | bearer | Mint a token (returns raw once). |
| `DELETE /api/ingest-tokens/{id}` | bearer | Revoke (tenant-scoped). |
| `POST /api/ingest` | `X-Ingest-Token` | Remote log ingestion. |

`/api/auth/signup`, `/api/auth/login`, and `/api/ingest` are in the auth
middleware's open-paths list (signup/login happen before a token exists;
ingest uses its own `X-Ingest-Token` header).

### Remote ingestion

`POST /api/ingest` authenticates with the `X-Ingest-Token` header,
resolves it to an `account_id`, screens each submitted log line against
the watcher's error patterns server-side, and feeds matching lines into
`orchestrator.handle_event()` as `LogEvent`s tagged with the tenant. The
existing dedup + escalation-cooldown logic means a log storm collapses to
a single incident.

```bash
curl -X POST https://YOUR_SENTRY_HOST/api/ingest \
  -H "X-Ingest-Token: sing_xxxxxxxxxxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{"lines": ["ERROR: redis connection refused"]}'
```

### Frontend

- `auth/AuthContext.jsx` — session state, `login`/`signup`/`logout`,
  re-validates a persisted token via `/api/auth/me` on load.
- `auth/AuthScreen.jsx` — combined login/signup card (shown when anonymous).
- `components/ConnectService.jsx` — the onboarding panel: mint/list/revoke
  ingestion tokens, copy-paste `curl` snippet.
- `App.jsx` — now an auth gate: splash while validating → `AuthScreen`
  when anonymous → dashboard (with `ConnectService` on top + Log out in
  the header) when authenticated.

## Deploying on Render

A Render Blueprint (`render.yaml` at the repo root) provisions the whole
stack in one click (`render blueprint launch`, or connect the repo in the
Render dashboard):

| Service | Type | Notes |
|---------|------|-------|
| `sentry-db` | Postgres 16 | `DATABASE_URL` wired automatically via `fromDatabase`. |
| `sentry-api` | Docker web service | FastAPI backend. `healthCheckPath: /api/health`. A `preDeployCommand` runs Alembic migrations (`python -m alembic -c backend/persistence/alembic.ini upgrade head`) before each new version goes live. |
| `sentry-frontend` | Static site | Vite build (`npm ci && npm run build` → `frontend/dist`). `/api/*` is rewritten to the backend; all other paths fall back to `index.html` (SPA). |

### LLM provider — AWS Bedrock Access Gateway

Sentry talks to an **OpenAI-compatible AWS Bedrock Access Gateway** rather
than the Anthropic API directly. This is set via `LLM_PROVIDER=bedrock_gateway`
+ `BEDROCK_GATEWAY_BASE_URL` (the `/api/v1` root) + `BEDROCK_GATEWAY_API_KEY`
(secret). The gateway exposes many Bedrock models (list them with
`curl -H "Authorization: Bearer $KEY" $BASE_URL/models`); Sentry defaults to
`us.anthropic.claude-opus-4-8`, the strongest Opus tier available, for its
agentic triage/remediation pipeline. The `openai` SDK (already a dependency)
is pointed at the gateway URL by `BedrockGatewayLLMClient`.

Secrets you set in the Render dashboard (marked `sync: false` in the
blueprint so they're never committed):

- `BEDROCK_GATEWAY_API_KEY` — the gateway key (the base URL + model are
  non-secret and pre-set in `render.yaml`).
- `CF_ACCESS_TEAM_DOMAIN` / `CF_ACCESS_AUD` — enable Cloudflare Access auth.

### Putting Cloudflare Access in front

1. Add a custom hostname (DNS managed in Cloudflare, **proxied/orange-cloud**)
   pointing at the Render frontend service.
2. In Zero Trust → Access → Applications, create a **self-hosted**
   application on that hostname. Pick an identity provider (e.g. one-time
   PIN / email OTP, Google, GitHub…).
3. Copy the application's **Audience (AUD)** tag into `CF_ACCESS_AUD` and
   your team domain into `CF_ACCESS_TEAM_DOMAIN`.
4. Add a policy that **bypasses** `/api/ingest` (so log shippers reach it
   without a browser session) and requires authentication for everything
   else.

Because the SPA proxies `/api/*` to the backend, the browser only ever
talks to one origin — the one Cloudflare Access protects.

### Provisioned Cloudflare Access setup (this deployment)

The Zero Trust resources for `aindoori.com` are already created via the
Cloudflare API:

| Item | Value |
|------|-------|
| Team domain (`CF_ACCESS_TEAM_DOMAIN`) | `aindoori.cloudflareaccess.com` |
| Access app | **Sentry** → `sentry.aindoori.com` (app id `d1852314-9ce1-4054-8cc7-44e89f9979b4`) |
| App AUD (`CF_ACCESS_AUD`) | `745e4f9c43b58d6ba44fa86f834dc5a85d6010321f048546f687dce1071455c5` |
| Allow policy | email `indooriaditya@gmail.com` |
| Ingest bypass app | **Sentry ingest (public)** → `sentry.aindoori.com/api/ingest` with a `bypass: everyone` policy (app id `c3f1f73c-199d-4a38-8964-590d4e27b42d`) |

Both `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_AUD` are baked into `render.yaml`
as plain (non-secret) values — they only identify which signed JWT to trust;
the actual trust is the RS256 signature verified against Cloudflare's public
JWKS at `https://aindoori.cloudflareaccess.com/cdn-cgi/access/certs`.

**Remaining manual steps to go live:**
1. `render blueprint launch` (set `BEDROCK_GATEWAY_API_KEY` secret in the
   dashboard).
2. In Cloudflare DNS for `aindoori.com`, add a **proxied** CNAME
   `sentry` → the Render frontend (`sentry-frontend.onrender.com`), and add
   `sentry.aindoori.com` as a custom domain on the Render frontend service.
3. Pick a login method (email OTP works out of the box) under
   Zero Trust → Settings → Authentication if none is configured yet.
4. Visit `https://sentry.aindoori.com` — Cloudflare prompts for login; after
   authenticating as `indooriaditya@gmail.com` the dashboard loads with the
   account auto-provisioned.

## Tests

`backend/tests/test_saas.py` (14 tests): password primitives, account repo
(create/dupe/authenticate), ingestion-token repo (mint/resolve/revoke +
cross-tenant isolation), and a full TestClient flow
(signup → /me → mint → ingest → tenant-tagged event; duplicate signup 409;
bad ingest token 401). Frontend: existing 31 vitest tests still pass.

## Not yet built (future work)

- Email verification + password reset.
- OAuth / SSO sign-in.
- Per-tenant LLM API keys + per-tenant cost quotas / billing.
- Tenant-scoped reads on `/api/incidents` & `/api/memory` (the ingestion
  write path is fully tenant-scoped; the dashboard read endpoints still
  show the process-wide in-memory active set — wiring them to read
  `incident_repo` filtered by `account_id` is the next increment).
- Full per-tenant orchestrator isolation (today one orchestrator handles
  all tenants; incidents are *data*-scoped by `account_id`).
- A first-party log-shipping agent / sidecar image.
