"""
P4.2 — ``revoke_token`` CLI.

Marks a persisted API token as revoked by its id. Subsequent
:func:`backend.api.auth.hydrate_registry_from_repo` calls will add the
token's hash to the revocation set on boot, and live processes that
keep a long-lived registry can call :meth:`TokenRegistry.revoke_by_hash`
to drop it immediately.

Usage
-----

    python -m backend.scripts.revoke_token <token_id>

The ``token_id`` is the short identifier printed by
``create_admin_token`` (first 12 chars of the token hash).
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
        updated = await repo.revoke(args.token_id)
    finally:
        await database.engine.dispose()

    if not updated:
        print(f"No active token found with id={args.token_id}", file=sys.stderr)
        return 1
    print(f"✅  Token {args.token_id} revoked.", file=sys.stderr)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m backend.scripts.revoke_token",
        description="Revoke an API bearer token by id.",
    )
    parser.add_argument("token_id", help="Short 12-char token id (see create_admin_token output).")
    args = parser.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
