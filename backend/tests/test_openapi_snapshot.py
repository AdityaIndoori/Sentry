"""
P4.4 — OpenAPI snapshot test.

Locks in the public REST surface so frontend consumers (including the
React dashboard in ``frontend/``) get a stable contract.

The test is a **two-way street**:

* If you delete or rename a route, the snapshot comparison fails and
  you have to explain why — either the frontend change is landing in
  the same PR, or the removal is a breaking change and needs a
  deprecation path.
* If you add a NEW route, re-run with the env var ``SENTRY_UPDATE_
  OPENAPI_SNAPSHOT=1`` set and the snapshot file is rewritten. Commit
  the diff so reviewers can see the new surface area.

Snapshot location: ``backend/frontend_contract/openapi_snapshot.json``.
We compare a NORMALIZED subset of the OpenAPI schema — paths, methods,
parameters, request body shapes, response codes — not every jitter-y
detail pydantic-generated schemas throw off (titles, descriptions,
example values). That keeps false positives low while still catching
real contract breaks.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

SNAPSHOT_PATH = Path(__file__).parent.parent / "frontend_contract" / "openapi_snapshot.json"


def _normalize_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Keep the bits that matter for a contract, drop the noisy ones.

    Rationale:
      * ``title`` / ``description`` / ``example`` wobble with docstring
        edits and shouldn't fail a contract test.
      * ``default`` depends on the Pydantic model's runtime default,
        which can legitimately change.
      * ``$ref`` + ``$defs`` are preserved so structural refs still
        catch real breaks.
    """
    if not isinstance(schema, dict):
        return schema  # type: ignore[return-value]

    normalized: dict[str, Any] = {}
    for key, value in sorted(schema.items()):
        if key in {"title", "description", "example", "summary"}:
            continue
        if isinstance(value, dict):
            normalized[key] = _normalize_schema(value)
        elif isinstance(value, list):
            normalized[key] = [
                _normalize_schema(v) if isinstance(v, dict) else v for v in value
            ]
        else:
            normalized[key] = value
    return normalized


def _extract_surface(spec: dict[str, Any]) -> dict[str, Any]:
    """Produce a deterministic, contract-only view of an OpenAPI spec."""
    paths: dict[str, Any] = {}
    for path, operations in sorted((spec.get("paths") or {}).items()):
        by_method: dict[str, Any] = {}
        for method, op in sorted(operations.items()):
            if not isinstance(op, dict):
                continue
            by_method[method] = {
                "parameters": [
                    {
                        "name": p.get("name"),
                        "in": p.get("in"),
                        "required": p.get("required", False),
                    }
                    for p in sorted(
                        op.get("parameters") or [],
                        key=lambda x: (x.get("name", ""), x.get("in", "")),
                    )
                ],
                "request_body_required": (
                    op.get("requestBody", {}).get("required", False)
                    if op.get("requestBody")
                    else False
                ),
                "response_codes": sorted((op.get("responses") or {}).keys()),
            }
        paths[path] = by_method

    components = spec.get("components", {}) or {}
    schemas = components.get("schemas", {}) or {}
    normalized_schemas = {
        name: _normalize_schema(body) for name, body in sorted(schemas.items())
    }
    return {
        "paths": paths,
        "components": {"schemas": normalized_schemas},
    }


@pytest.fixture(scope="module")
def openapi_spec() -> dict[str, Any]:
    """Build the FastAPI app via the production composition root and
    return its full OpenAPI schema."""
    from backend.api.app import create_app

    app = create_app()
    return app.openapi()


def test_openapi_surface_matches_snapshot(openapi_spec: dict[str, Any]) -> None:
    """The contract test itself."""
    current = _extract_surface(openapi_spec)

    # Rewrite mode — for when a PR intentionally changes the surface.
    if os.environ.get("SENTRY_UPDATE_OPENAPI_SNAPSHOT") == "1":
        SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT_PATH.write_text(
            json.dumps(current, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        pytest.skip(
            f"Snapshot rewritten at {SNAPSHOT_PATH}. "
            "Unset SENTRY_UPDATE_OPENAPI_SNAPSHOT and re-run.",
        )

    if not SNAPSHOT_PATH.exists():
        # First run — seed the snapshot. Subsequent runs will compare.
        SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT_PATH.write_text(
            json.dumps(current, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        pytest.skip(f"Seeded OpenAPI snapshot at {SNAPSHOT_PATH}.")

    expected = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))

    assert current == expected, (
        "OpenAPI surface changed.\n"
        "If this is intentional, re-run pytest with:\n"
        "  SENTRY_UPDATE_OPENAPI_SNAPSHOT=1 python -m pytest "
        "backend/tests/test_openapi_snapshot.py\n"
        "and commit the updated openapi_snapshot.json.\n"
    )


def test_openapi_has_expected_top_level_routes(openapi_spec: dict[str, Any]) -> None:
    """Independent sanity check — even without a snapshot, certain routes
    MUST exist or we've broken a documented contract."""
    paths = openapi_spec.get("paths") or {}
    expected = {
        "/api/health",
        "/api/ready",
        "/api/status",
        "/api/incidents",
        "/api/trigger",
        "/api/memory",
        "/api/tools",
        "/api/security",
        "/api/config",
        "/api/watcher/start",
        "/api/watcher/stop",
        "/api/stream/incidents",
        # P4.6 — REST token-management endpoints.
        "/api/tokens",
    }
    missing = expected - set(paths.keys())
    assert not missing, f"OpenAPI spec is missing expected routes: {missing}"
