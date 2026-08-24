"""Add secure email links and account security fencing."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_email_links"
down_revision: str | Sequence[str] | None = "0003_google_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "epok_auth"


def upgrade() -> None:
    op.add_column(
        "user_account",
        sa.Column(
            "email_link_login_enabled",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        schema=SCHEMA,
    )
    op.add_column(
        "user_account",
        sa.Column("security_version", sa.Integer(), server_default="0", nullable=False),
        schema=SCHEMA,
    )
    op.create_check_constraint(
        "ck_epok_auth_user_security_version",
        "user_account",
        "security_version >= 0",
        schema=SCHEMA,
    )
    op.create_table(
        "email_link",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("recipient_hash", sa.Text(), nullable=False),
        sa.Column("browser_hash", sa.Text(), nullable=True),
        sa.Column("security_version", sa.Integer(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(purpose = 'login' AND browser_hash IS NOT NULL) "
            "OR (purpose <> 'login' AND browser_hash IS NULL)",
            name="ck_epok_auth_email_link_browser",
        ),
        sa.CheckConstraint(
            "length(token_hash) = 64 AND length(recipient_hash) = 64 "
            "AND (browser_hash IS NULL OR length(browser_hash) = 64)",
            name="ck_epok_auth_email_link_hashes",
        ),
        sa.CheckConstraint(
            "purpose IN ('login', 'password_reset', 'invitation')",
            name="ck_epok_auth_email_link_purpose",
        ),
        sa.CheckConstraint(
            "state IN ('pending', 'active', 'failed', 'consumed', 'revoked')",
            name="ck_epok_auth_email_link_state",
        ),
        sa.CheckConstraint(
            "created_at < expires_at "
            "AND (delivered_at IS NULL OR delivered_at >= created_at) "
            "AND (consumed_at IS NULL OR consumed_at >= created_at) "
            "AND (revoked_at IS NULL OR revoked_at >= created_at)",
            name="ck_epok_auth_email_link_times",
        ),
        sa.CheckConstraint(
            "generation > 0 AND security_version >= 0",
            name="ck_epok_auth_email_link_versions",
        ),
        sa.CheckConstraint(
            "(state = 'pending' AND delivered_at IS NULL AND consumed_at IS NULL "
            "AND revoked_at IS NULL) OR "
            "(state = 'active' AND delivered_at IS NOT NULL AND consumed_at IS NULL "
            "AND revoked_at IS NULL) OR "
            "(state = 'failed' AND delivered_at IS NULL AND consumed_at IS NULL "
            "AND revoked_at IS NOT NULL) OR "
            "(state = 'consumed' AND delivered_at IS NOT NULL AND consumed_at IS NOT NULL "
            "AND revoked_at IS NULL) OR "
            "(state = 'revoked' AND consumed_at IS NULL AND revoked_at IS NOT NULL)",
            name="ck_epok_auth_email_link_state_times",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{SCHEMA}.user_account.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "token_hash",
            name="uq_epok_auth_email_link_token_hash",
        ),
        sa.UniqueConstraint(
            "user_id",
            "purpose",
            "generation",
            name="uq_epok_auth_email_link_generation",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_epok_auth_email_link_state_expiry",
        "email_link",
        ["state", "expires_at"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_epok_auth_email_link_user_purpose",
        "email_link",
        ["user_id", "purpose", "generation"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_index(
        "ix_epok_auth_email_link_created",
        "email_link",
        ["created_at"],
        unique=False,
        schema=SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_epok_auth_email_link_created",
        table_name="email_link",
        schema=SCHEMA,
    )
    op.drop_index(
        "ix_epok_auth_email_link_user_purpose",
        table_name="email_link",
        schema=SCHEMA,
    )
    op.drop_index(
        "ix_epok_auth_email_link_state_expiry",
        table_name="email_link",
        schema=SCHEMA,
    )
    op.drop_table("email_link", schema=SCHEMA)
    op.drop_constraint(
        "ck_epok_auth_user_security_version",
        "user_account",
        type_="check",
        schema=SCHEMA,
    )
    op.drop_column("user_account", "security_version", schema=SCHEMA)
    op.drop_column("user_account", "email_link_login_enabled", schema=SCHEMA)
