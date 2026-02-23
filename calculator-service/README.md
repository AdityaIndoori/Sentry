# CalcAPI — Buggy Calculator for Testing Sentry

A Flask calculator API with **4 intentional bugs** for testing Sentry's self-healing capabilities.

## The 4 Bugs

| # | Bug | File | Error | Trigger |
|---|-----|------|-------|---------|
| 1 | **PRECISION=-1** | `config/settings.py:12` | `round(x, -1)` gives wrong results (rounds to nearest 10) | Any calculation |
| 2 | **No zero check** in divide | `routes/calculate.py:17` | `ZeroDivisionError` | `divide` with `b=0` |
| 3 | **Missing `import json`** | `routes/history.py` | `NameError: name 'json' is not defined` | GET `/api/history` |
| 4 | **`^` instead of `**`** for power | `routes/calculate.py:19` | Wrong result (XOR not exponentiation) | `power` operation |

## Running

```bash
cd calculator-service
pip install -r requirements.txt
python app.py
```

Runs on port 5002.

## Trigger Each Bug

```bash
# Bug #1: PRECISION=-1 — add 1.5 + 2.3 should be 3.8 but rounds to 0.0
curl -X POST http://localhost:5002/api/calculate -H "Content-Type: application/json" -d '{"operation":"add","a":1.5,"b":2.3}'

# Bug #2: ZeroDivisionError
curl -X POST http://localhost:5002/api/calculate -H "Content-Type: application/json" -d '{"operation":"divide","a":10,"b":0}'

# Bug #3: NameError — missing json import
curl http://localhost:5002/api/history

# Bug #4: power uses ^ (XOR) — 2 power 8 should be 256, returns 10
curl -X POST http://localhost:5002/api/calculate -H "Content-Type: application/json" -d '{"operation":"power","a":2,"b":8}'

# Working endpoint (no bug):
curl http://localhost:5002/health
```

## Using with Sentry

In your `.env`:
```env
SERVICE_HOST_PATH=/path/to/calculator-service
WATCH_PATHS=/app/watched/*.log,/app/workspace/logs/*.log
SERVICE_RESTART_CMD=docker restart calcapi
```
