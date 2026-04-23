"""P1.2 initial schema — incidents, memory, audit log, api tokens

Revision ID: 20260422_0001
Revises:
Create Date: 2026-04-22 02:30:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# Revision identifiers, used by Alembic.
revision: str = "20260422_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── incidents ──────────────────────────────────────────────────
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("symptom", sa.Text, nullable=False),
        sa.Column("root_cause", sa.Text, nullable=True),
        sa.Column("fix_applied", sa.Text, nullable=True),
        sa.Column("triage_result", sa.Text, nullable=True),
        sa.Column("commit_id", sa.String(64), nullable=True),
        sa.Column("retry_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("cost_usd", sa.Float, nullable=False, server_default="0"),
        sa.Column("fingerprint_hash", sa.String(64), nullable=True),
        sa.Column("activity_log", sa.JSON, nullable=False),
        sa.Column("log_events", sa.JSON, nullable=False),
        sa.Column("vectors", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incidents_state", "incidents", ["state"])
    op.create_index("ix_incidents_created_at", "incidents", ["created_at"])
    op.create_index(
        "ix_incidents_fingerprint_hash", "incidents", ["fingerprint_hash"]
    )
    op.create_index(
        "ix_incidents_state_created",
        "incidents",
        ["state", sa.text("created_at DESC")],
    )

    # ── memory_entries ─────────────────────────────────────────────
    op.create_table(
        "memory_entries",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("symptom", sa.Text, nullable=False),
        sa.Column("root_cause", sa.Text, nullable=False),
        sa.Column("fix", sa.Text, nullable=False),
        sa.Column("vectors", sa.JSON, nullable=False),
        sa.Column("timestamp", sa.String(64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_memory_entries_created_at", "memory_entries", ["created_at"]
    )

    # ── memory_state (singleton kv) ────────────────────────────────
    op.create_table(
        "memory_state",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.Text, nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # ── audit_log ──────────────────────────────────────────────────
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("timestamp_iso", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("detail", sa.Text, nullable=False, server_default=""),
        sa.Column("result", sa.Text, nullable=False, server_default=""),
        sa.Column("chain_of_thought", sa.Text, nullable=False, server_default=""),
        sa.Column("extra_metadata", sa.JSON, nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("entry_hash", sa.String(64), nullable=False, unique=True),
    )
    op.create_index("ix_audit_log_timestamp", "audit_log", ["timestamp"])
    op.create_index("ix_audit_log_agent_id", "audit_log", ["agent_id"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])

    # ── audit_log immutability trigger (SEC-30) ─────────────────────
    #
    # The application layer already refuses to issue UPDATE or DELETE
    # against audit_log, but we add a DB-level trigger as a second line
    # of defense so a rogue operator with direct database access still
    # cannot rewrite forensic history without leaving a clear paper
    # trail.
    #
    # * Postgres path:   RAISE EXCEPTION inside a PL/pgSQL function
    #                    bound to a BEFORE UPDATE OR DELETE trigger.
    # * SQLite path:     two BEFORE UPDATE / BEFORE DELETE triggers
    #                    that call RAISE(ABORT, ...), which aborts
    #                    the statement and propagates as an
    #                    sqlite3.IntegrityError to the Python layer.
    #                    This gives dev / test / staging SQLite
    #                    deployments the same defense-in-depth as
    #                    production Postgres.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            """
            CREATE OR REPLACE FUNCTION sentry_audit_log_immutable()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION
                    'audit_log is append-only: % rejected',
                    TG_OP
                    USING ERRCODE = '42000';
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        op.execute(
            """
            CREATE TRIGGER sentry_audit_log_no_update
            BEFORE UPDATE OR DELETE ON audit_log
            FOR EACH ROW EXECUTE FUNCTION sentry_audit_log_immutable();
            """
        )
    elif bind.dialect.name == "sqlite":
        op.execute(
            """
            CREATE TRIGGER sentry_audit_log_no_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE rejected');
            END;
            """
        )
        op.execute(
            """
            CREATE TRIGGER sentry_audit_log_no_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log is append-only: DELETE rejected');
            END;
            """
        )


    # ── api_tokens (P2.1 uses this) ────────────────────────────────
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("scopes", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_tokens_token_hash", "api_tokens", ["token_hash"])


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS sentry_audit_log_no_update ON audit_log;")
        op.execute("DROP FUNCTION IF EXISTS sentry_audit_log_immutable();")

    op.drop_index("ix_api_tokens_token_hash", table_name="api_tokens")
    op.drop_table("api_tokens")

    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_index("ix_audit_log_agent_id", table_name="audit_log")
    op.drop_index("ix_audit_log_timestamp", table_name="audit_log")
    op.drop_table("audit_log")

    op.drop_table("memory_state")

    op.drop_index("ix_memory_entries_created_at", table_name="memory_entries")
    op.drop_table("memory_entries")

    op.drop_index("ix_incidents_state_created", table_name="incidents")
    op.drop_index("ix_incidents_fingerprint_hash", table_name="incidents")
    op.drop_index("ix_incidents_created_at", table_name="incidents")
    op.drop_index("ix_incidents_state", table_name="incidents")
    op.drop_table("incidents")
