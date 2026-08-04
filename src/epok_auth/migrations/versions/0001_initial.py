"""Create epok-auth users, refresh sessions, and security events.

Revision ID: 0001_initial
Revises: None
Create Date: 2026-08-04
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "epok_auth"


def upgrade() -> None:
    op.execute(sa.schema.CreateSchema(SCHEMA, if_not_exists=True))

    op.create_table(
        "user_account",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default="active", nullable=False),
        sa.Column(
            "roles",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "scopes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "failed_login_attempts",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "jsonb_typeof(roles) = 'array' AND jsonb_typeof(scopes) = 'array'",
            name="ck_epok_auth_user_capabilities_arrays",
        ),
        sa.CheckConstraint(
            "length(display_name) BETWEEN 1 AND 200",
            name="ck_epok_auth_user_display_name_length",
        ),
        sa.CheckConstraint(
            "email = lower(email)",
            name="ck_epok_auth_user_email_normalized",
        ),
        sa.CheckConstraint(
            "length(email) BETWEEN 3 AND 320",
            name="ck_epok_auth_user_email_length",
        ),
        sa.CheckConstraint(
            "failed_login_attempts >= 0",
            name="ck_epok_auth_user_failed_attempts",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'disabled')",
            name="ck_epok_auth_user_status",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email", name="uq_epok_auth_user_email"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_epok_auth_user_roles_gin",
        "user_account",
        ["roles"],
        unique=False,
        schema=SCHEMA,
        postgresql_using="gin",
    )
    op.create_index(
        "ix_epok_auth_user_status",
        "user_account",
        ["status"],
        unique=False,
        schema=SCHEMA,
    )

    op.create_table(
        "refresh_session",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("family_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("csrf_hash", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "idle_expires_at <= absolute_expires_at AND created_at < absolute_expires_at",
            name="ck_epok_auth_refresh_expiry_order",
        ),
        sa.CheckConstraint(
            "length(token_hash) = 64 AND length(csrf_hash) = 64",
            name="ck_epok_auth_refresh_hash_lengths",
        ),
        sa.CheckConstraint(
            "(used_at IS NULL AND replaced_by_id IS NULL) OR "
            "(used_at IS NOT NULL AND replaced_by_id IS NOT NULL)",
            name="ck_epok_auth_refresh_replacement_pair",
        ),
        sa.ForeignKeyConstraint(
            ["replaced_by_id"],
            [f"{SCHEMA}.refresh_session.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{SCHEMA}.user_account.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("replaced_by_id", name="uq_epok_auth_refresh_replacement"),
        sa.UniqueConstraint("token_hash", name="uq_epok_auth_refresh_token_hash"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_epok_auth_refresh_expiry",
        "refresh_session",
        ["idle_expires_at", "absolute_expires_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_epok_auth_refresh_family",
        "refresh_session",
        ["family_id"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_epok_auth_refresh_user",
        "refresh_session",
        ["user_id"],
        unique=False,
        schema=SCHEMA,
    )

    op.create_table(
        "security_event",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("session_id", sa.Uuid(), nullable=True),
        sa.Column("request_id", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.Text(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column(
            "event_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(event_type) BETWEEN 1 AND 100",
            name="ck_epok_auth_event_type_length",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            [f"{SCHEMA}.refresh_session.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{SCHEMA}.user_account.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_epok_auth_event_type_time",
        "security_event",
        ["event_type", "occurred_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_epok_auth_event_user_time",
        "security_event",
        ["user_id", "occurred_at"],
        unique=False,
        schema=SCHEMA,
    )


def downgrade() -> None:
    op.drop_index("ix_epok_auth_event_user_time", table_name="security_event", schema=SCHEMA)
    op.drop_index("ix_epok_auth_event_type_time", table_name="security_event", schema=SCHEMA)
    op.drop_table("security_event", schema=SCHEMA)
    op.drop_index("ix_epok_auth_refresh_user", table_name="refresh_session", schema=SCHEMA)
    op.drop_index("ix_epok_auth_refresh_family", table_name="refresh_session", schema=SCHEMA)
    op.drop_index("ix_epok_auth_refresh_expiry", table_name="refresh_session", schema=SCHEMA)
    op.drop_table("refresh_session", schema=SCHEMA)
    op.drop_index("ix_epok_auth_user_status", table_name="user_account", schema=SCHEMA)
    op.drop_index("ix_epok_auth_user_roles_gin", table_name="user_account", schema=SCHEMA)
    op.drop_table("user_account", schema=SCHEMA)
    op.execute(sa.schema.DropSchema(SCHEMA, if_exists=True))
