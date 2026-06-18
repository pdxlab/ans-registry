"""initial schema

Initial schema for the ans-registry service. Six tables:
  - agent                  — registered AI agent (registry row)
  - transfer               — ownership transfer record
  - lookuplog              — public lookup analytics
  - a2averificationlog     — agent-to-agent verification audit
  - adminuser              — admin accounts (separate from agents)
  - adminsession           — browser sessions (24-hour TTL)

Postgres-only BRIN indexes on the high-volume timestamp columns are
applied via a dialect guard so SQLite-based dev/tests still work.

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-18
"""

from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel  # noqa: F401  — used in the column definitions below
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── tables ──────────────────────────────────────────────────────────────
    op.create_table(
        "a2averificationlog",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("caller_ans_name", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("target_ans_name", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("result", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("requester_ip", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("verified_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "adminuser",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("email", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("password_hash", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("salt", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("role", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("api_key", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_login", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_adminuser_email"), "adminuser", ["email"], unique=True)

    op.create_table(
        "agent",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("ans_name", sqlmodel.sql.sqltypes.AutoString(length=100), nullable=False),
        sa.Column("display_name", sqlmodel.sql.sqltypes.AutoString(length=255), nullable=False),
        sa.Column("owner_org", sqlmodel.sql.sqltypes.AutoString(length=255), nullable=False),
        sa.Column("owner_email", sqlmodel.sql.sqltypes.AutoString(length=255), nullable=False),
        sa.Column("owner_domain", sqlmodel.sql.sqltypes.AutoString(length=255), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("verification_method", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("verification_token", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.Column("assurance_tier", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("org_validated", sa.Boolean(), nullable=False),
        sa.Column("org_validated_by", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("agent_type", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("description", sqlmodel.sql.sqltypes.AutoString(length=1000), nullable=False),
        sa.Column("capabilities", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("model_used", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("data_access", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("source_url", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("trust_score", sa.Float(), nullable=True),
        sa.Column("trust_tier", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("trust_evaluated_at", sa.DateTime(), nullable=True),
        sa.Column("trust_cert_url", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("status", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("orphan_risk", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("registered_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_agent_ans_name"), "agent", ["ans_name"], unique=True)

    op.create_table(
        "lookuplog",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("ans_name", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("requester_ip", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("looked_up_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "adminsession",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("admin_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["admin_id"], ["adminuser.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "transfer",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("agent_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("ans_name", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("from_org", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("from_email", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("to_org", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("to_email", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("to_domain", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("status", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("transfer_token", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("initiated_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["agent_id"], ["agent.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── B-tree indexes autogenerate misses (work on every dialect) ──────────
    op.create_index("ix_agent_owner_domain", "agent", ["owner_domain"])
    op.create_index(
        "ix_agent_status_assurance_tier", "agent", ["status", "assurance_tier"]
    )
    op.create_index("ix_agent_verification_token", "agent", ["verification_token"])
    op.create_index("ix_transfer_agent_id", "transfer", ["agent_id"])
    op.create_index("ix_transfer_transfer_token", "transfer", ["transfer_token"])
    op.create_index("ix_adminsession_expires_at", "adminsession", ["expires_at"])

    # ── BRIN indexes for time-ordered, append-only tables (Postgres only) ──
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            "CREATE INDEX ix_lookuplog_looked_up_at_brin "
            "ON lookuplog USING BRIN (looked_up_at)"
        )
        op.execute(
            "CREATE INDEX ix_a2averificationlog_verified_at_brin "
            "ON a2averificationlog USING BRIN (verified_at)"
        )
    else:
        # Fallback B-tree indexes for SQLite (dev/test parity).
        op.create_index("ix_lookuplog_looked_up_at", "lookuplog", ["looked_up_at"])
        op.create_index(
            "ix_a2averificationlog_verified_at", "a2averificationlog", ["verified_at"]
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP INDEX IF EXISTS ix_lookuplog_looked_up_at_brin")
        op.execute("DROP INDEX IF EXISTS ix_a2averificationlog_verified_at_brin")
    else:
        op.drop_index(
            "ix_a2averificationlog_verified_at", table_name="a2averificationlog"
        )
        op.drop_index("ix_lookuplog_looked_up_at", table_name="lookuplog")

    op.drop_index("ix_adminsession_expires_at", table_name="adminsession")
    op.drop_index("ix_transfer_transfer_token", table_name="transfer")
    op.drop_index("ix_transfer_agent_id", table_name="transfer")
    op.drop_index("ix_agent_verification_token", table_name="agent")
    op.drop_index("ix_agent_status_assurance_tier", table_name="agent")
    op.drop_index("ix_agent_owner_domain", table_name="agent")

    op.drop_table("transfer")
    op.drop_table("adminsession")
    op.drop_table("lookuplog")
    op.drop_index(op.f("ix_agent_ans_name"), table_name="agent")
    op.drop_table("agent")
    op.drop_index(op.f("ix_adminuser_email"), table_name="adminuser")
    op.drop_table("adminuser")
    op.drop_table("a2averificationlog")
