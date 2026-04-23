"""
P4.2 — operator CLIs.

Each module in this package is a self-contained CLI. They share the
composition root (``backend.shared.factory.build_container``) so their
behaviour matches what the live service sees, including secrets
provider + DB URL selection.

Run:

    python -m backend.scripts.create_admin_token  --help
    python -m backend.scripts.revoke_token        --help
    python -m backend.scripts.list_tokens         --help
"""
