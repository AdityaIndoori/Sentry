"""
P4.2 — ``create_admin_token`` CLI.

Mints a fresh API bearer token, persists its SHA-256 hash to the
``api_tokens`` table, and prints the **raw token once** to stdout.
After this script exits the raw token can never be recovered — if
it's lost the operator mints a new one.

Usage
-----

    python -m backend.scripts.create_admin_token \
        --name grafana-dashboard --role admin --scopes "*"

    python -m backend.scripts.create_admin_token \
        --name watcher-only --role operator \
        --scopes "incidents:read,watcher:control"

The DB URL is read from the usual settings pipeline (``DATABASE_URL``
env var + the active secrets backend). In dev mode with no
``DATABASE_URL`` set we fall back to the synthesized SQLite file —
exactly the same path the running backend uses — so tokens minted
here are live when the process starts.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections.abc import Sequence

from backend.persistence.repositories.token_repo import TokenRepository
from backend.persistence.session import build_database
from backend.shared.principal import generate_token, hash_token
from backend.shared.settings import get_settings

logger = logging.getLogger(__name__)


def _parse_scopes(raw: str) -> list[str]:
    scopes = [s.strip() for s in raw.split(",") if s.strip()]
    if not scopes:
        raise SystemExit("--scopes must be non-empty (use '*' for admin wildcard).")
    return scopes


async def _run(args: argparse.Namespace) -> int:
    settings = get_settings()
    database_url = settings.database_url
    if not database_url:
        # Use the same synthesised sqlite path the factory uses so the
        # running backend and this CLI read/write the same file.
        import os

        data_dir = os.path.dirname(settings.memory_file_path) or "."
        os.makedirs(data_dir, exist_ok=True)
        database_url = (
            f"sqlite+aiosqlite:///{os.path.join(data_dir, 'sentry.db')}"
        )

    database = build_database(database_url)
    await database.create_all()
    repo = TokenRepository(database)

    raw_token = generate_token()
    token_hash = hash_token(raw_token)
    token_id = token_hash[:12]

    try:
        stored = await repo.create(
            token_id=token_id,
            token_hash=token_hash,
            name=args.name,
            role=args.role,
            scopes=args.scopes,
        )
    finally:
        await database.engine.dispose()

    print("", file=sys.stderr)
    print("✅  API token created.", file=sys.stderr)
    print("", file=sys.stderr)
    print(f"    id:      {stored.id}", file=sys.stderr)
    print(f"    name:    {stored.name}", file=sys.stderr)
    print(f"    role:    {stored.role}", file=sys.stderr)
    print(f"    scopes:  {list(stored.scopes)}", file=sys.stderr)
    print("", file=sys.stderr)
    print("⚠  The raw token below is shown ONCE. Store it in your", file=sys.stderr)
    print("   secrets backend right now — there is no recovery path.", file=sys.stderr)
    print("", file=sys.stderr)
    # Raw token goes to stdout so the caller can pipe it into a
    # secrets manager: `python -m ... | vault kv put ...`.
    print(raw_token)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m backend.scripts.create_admin_token",
        description="Mint a new API bearer token for Sentry.",
    )
    parser.add_argument("--name", required=True, help="Human-friendly label, e.g. 'grafana-dashboard'.")
    parser.add_argument(
        "--role",
        default="admin",
        choices=("admin", "operator", "read_only"),
        help="Role assigned to the principal (default: admin).",
    )
    parser.add_argument(
        "--scopes",
        default="*",
        type=_parse_scopes,
        help=(
            "Comma-separated list of scopes, or '*' for admin wildcard. "
            "Examples: 'incidents:read', "
            "'incidents:read,watcher:control,incidents:trigger'."
        ),
    )
    args = parser.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
