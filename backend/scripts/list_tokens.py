"""
P4.2 — ``list_tokens`` CLI.

Prints every persisted API token row as a human-readable table. The
raw tokens are NEVER displayed (the DB only stores their SHA-256
hash); this command is for operators to reconcile the live registry
against what's in persistence.

Usage
-----

    python -m backend.scripts.list_tokens              # active only
    python -m backend.scripts.list_tokens --all        # include revoked
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence

from backend.persistence.repositories.token_repo import TokenRepository
from backend.persistence.session import build_database
from backend.shared.settings import get_settings


async def _run(args: argparse.Namespace) -> int:
    settings = get_settings()
    database_url = settings.database_url
    if not database_url:
        import os

        data_dir = os.path.dirname(settings.memory_file_path) or "."
        os.makedirs(data_dir, exist_ok=True)
        database_url = (
            f"sqlite+aiosqlite:///{os.path.join(data_dir, 'sentry.db')}"
        )

    database = build_database(database_url)
    repo = TokenRepository(database)
    try:
        tokens = await repo.list_all(include_revoked=args.all)
    finally:
        await database.engine.dispose()

    if not tokens:
        print("(no tokens)", file=sys.stderr)
        return 0

    # Fixed-width columns for terminal legibility.
    print(f"{'ID':<14} {'NAME':<24} {'ROLE':<10} {'SCOPES':<30} {'CREATED':<20} STATUS")
    print("-" * 110)
    for t in tokens:
        status = "revoked" if t.is_revoked else "active"
        scopes = ",".join(t.scopes)[:28]
        created = t.created_at.strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"{t.id:<14} {t.name:<24} {t.role:<10} {scopes:<30} {created:<20} {status}"
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m backend.scripts.list_tokens",
        description="List persisted API bearer tokens (hashes only; raw tokens never stored).",
    )
    parser.add_argument("--all", action="store_true", help="Include revoked tokens in the output.")
    args = parser.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
