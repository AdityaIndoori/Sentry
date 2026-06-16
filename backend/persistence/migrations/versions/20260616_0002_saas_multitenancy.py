"""SaaS multi-tenancy — accounts, ingestion_tokens, incidents.account_id

Revision ID: 20260616_0002
Revises: 20260422_0001
Create Date: 2026-06-16 00:45:00.000000

Adds the two tables that turn Sentry into a multi-tenant SaaS:

* ``accounts``          — signed-up end users (email + PBKDF2 password hash).
* ``ingestion_tokens``  — per-account log-shipping keys (hashed).

…and a nullable ``account_id`` column on ``incidents`` so every incident
can be attributed to the tenant whose logs produced it. The column is
NULLABLE so pre-existing rows + the single-tenant / local-dev path keep
working unchanged.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic.
revision: str = "20260616_0002"
down_revision: Union[str, None] = "20260422_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── accounts ───────────────────────────────────────────────────
    op.create_table(
        "accounts",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False, server_default=""),
        sa.Column("default_mode", sa.String(16), nullable=False, server_default="audit"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_accounts_email", "accounts", ["email"], unique=True)

    # ── ingestion_tokens ───────────────────────────────────────────
    op.create_table(
        "ingestion_tokens",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("service_name", sa.String(128), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_ingestion_tokens_account_id", "ingestion_tokens", ["account_id"]
    )
    op.create_index(
        "ix_ingestion_tokens_token_hash", "ingestion_tokens", ["token_hash"], unique=True
    )

    # ── incidents.account_id (tenant scoping) ──────────────────────
    op.add_column(
        "incidents",
        sa.Column("account_id", sa.String(64), nullable=True),
    )
    op.create_index("ix_incidents_account_id", "incidents", ["account_id"])


def downgrade() -> None:
    op.drop_index("ix_incidents_account_id", table_name="incidents")
    op.drop_column("incidents", "account_id")

    op.drop_index("ix_ingestion_tokens_token_hash", table_name="ingestion_tokens")
    op.drop_index("ix_ingestion_tokens_account_id", table_name="ingestion_tokens")
    op.drop_table("ingestion_tokens")

    op.drop_index("ix_accounts_email", table_name="accounts")
    op.drop_table("accounts")
