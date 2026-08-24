"""Add Google identities, challenges, and account login state."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_google_identity"
down_revision: str | Sequence[str] | None = "0002_passkeys"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "epok_auth"


def upgrade() -> None:
    op.add_column(
        "user_account",
        sa.Column(
            "password_login_enabled",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        schema=SCHEMA,
    )
    op.add_column(
        "user_account",
        sa.Column(
            "google_auto_link_allowed",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        schema=SCHEMA,
    )
    op.create_table(
        "external_identity",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("email", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "email IS NULL OR length(email) BETWEEN 3 AND 320",
            name="ck_epok_auth_external_identity_email",
        ),
        sa.CheckConstraint(
            "length(issuer) BETWEEN 1 AND 255 AND length(subject) BETWEEN 1 AND 255",
            name="ck_epok_auth_external_identity_keys",
        ),
        sa.CheckConstraint(
            "last_login_at IS NULL OR last_login_at >= created_at",
            name="ck_epok_auth_external_identity_times",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{SCHEMA}.user_account.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "issuer",
            "subject",
            name="uq_epok_auth_external_identity_subject",
        ),
        sa.UniqueConstraint(
            "user_id",
            "issuer",
            name="uq_epok_auth_external_identity_user_issuer",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_epok_auth_external_identity_user",
        "external_identity",
        ["user_id"],
        unique=False,
        schema=SCHEMA,
    )
    op.create_table(
        "google_challenge",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("nonce", sa.Text(), nullable=False),
        sa.Column("origin", sa.Text(), nullable=False),
        sa.Column("client_id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "length(origin) BETWEEN 1 AND 2048 AND length(client_id) BETWEEN 20 AND 255",
            name="ck_epok_auth_google_challenge_context",
        ),
        sa.CheckConstraint(
            "length(nonce) BETWEEN 32 AND 255",
            name="ck_epok_auth_google_challenge_nonce",
        ),
        sa.CheckConstraint(
            "purpose IN ('login', 'link')",
            name="ck_epok_auth_google_challenge_purpose",
        ),
        sa.CheckConstraint(
            "created_at < expires_at AND (consumed_at IS NULL OR consumed_at >= created_at)",
            name="ck_epok_auth_google_challenge_times",
        ),
        sa.CheckConstraint(
            "(purpose = 'login' AND user_id IS NULL) OR (purpose = 'link' AND user_id IS NOT NULL)",
            name="ck_epok_auth_google_challenge_user",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{SCHEMA}.user_account.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("nonce", name="uq_epok_auth_google_challenge_nonce"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_epok_auth_google_challenge_expiry",
        "google_challenge",
        ["expires_at"],
        unique=False,
        schema=SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_epok_auth_google_challenge_expiry",
        table_name="google_challenge",
        schema=SCHEMA,
    )
    op.drop_table("google_challenge", schema=SCHEMA)
    op.drop_index(
        "ix_epok_auth_external_identity_user",
        table_name="external_identity",
        schema=SCHEMA,
    )
    op.drop_table("external_identity", schema=SCHEMA)
    op.drop_column("user_account", "google_auto_link_allowed", schema=SCHEMA)
    op.drop_column("user_account", "password_login_enabled", schema=SCHEMA)
