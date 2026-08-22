"""Add passkey credentials and single-use WebAuthn challenges."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_passkeys"
down_revision: str | Sequence[str] | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "epok_auth"


def upgrade() -> None:
    op.create_table(
        "passkey_credential",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("aaguid", sa.Text(), nullable=False),
        sa.Column(
            "transports",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("device_type", sa.Text(), nullable=False),
        sa.Column(
            "backed_up",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "length(aaguid) BETWEEN 1 AND 36",
            name="ck_epok_auth_passkey_aaguid",
        ),
        sa.CheckConstraint(
            "device_type IN ('single_device', 'multi_device')",
            name="ck_epok_auth_passkey_device_type",
        ),
        sa.CheckConstraint(
            "NOT backed_up OR device_type = 'multi_device'",
            name="ck_epok_auth_passkey_backup_state",
        ),
        sa.CheckConstraint(
            "octet_length(credential_id) BETWEEN 1 AND 1023",
            name="ck_epok_auth_passkey_credential_id_length",
        ),
        sa.CheckConstraint(
            "length(name) BETWEEN 1 AND 100",
            name="ck_epok_auth_passkey_name_length",
        ),
        sa.CheckConstraint(
            "octet_length(public_key) BETWEEN 1 AND 16384",
            name="ck_epok_auth_passkey_public_key_length",
        ),
        sa.CheckConstraint("sign_count >= 0", name="ck_epok_auth_passkey_sign_count"),
        sa.CheckConstraint(
            "jsonb_typeof(transports) = 'array'",
            name="ck_epok_auth_passkey_transports_array",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{SCHEMA}.user_account.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("credential_id", name="uq_epok_auth_passkey_credential_id"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_epok_auth_passkey_user",
        "passkey_credential",
        ["user_id"],
        unique=False,
        schema=SCHEMA,
    )

    op.create_table(
        "passkey_challenge",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("challenge", sa.LargeBinary(), nullable=False),
        sa.Column("origin", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "octet_length(challenge) = 32",
            name="ck_epok_auth_passkey_challenge_length",
        ),
        sa.CheckConstraint(
            "length(origin) BETWEEN 1 AND 2048",
            name="ck_epok_auth_passkey_challenge_origin_length",
        ),
        sa.CheckConstraint(
            "purpose IN ('registration', 'authentication')",
            name="ck_epok_auth_passkey_challenge_purpose",
        ),
        sa.CheckConstraint(
            "created_at < expires_at AND (consumed_at IS NULL OR consumed_at >= created_at)",
            name="ck_epok_auth_passkey_challenge_times",
        ),
        sa.CheckConstraint(
            "(purpose = 'registration' AND user_id IS NOT NULL) OR "
            "(purpose = 'authentication' AND user_id IS NULL)",
            name="ck_epok_auth_passkey_challenge_user",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{SCHEMA}.user_account.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("challenge", name="uq_epok_auth_passkey_challenge"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_epok_auth_passkey_challenge_expiry",
        "passkey_challenge",
        ["expires_at"],
        unique=False,
        schema=SCHEMA,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_epok_auth_passkey_challenge_expiry",
        table_name="passkey_challenge",
        schema=SCHEMA,
    )
    op.drop_table("passkey_challenge", schema=SCHEMA)
    op.drop_index(
        "ix_epok_auth_passkey_user",
        table_name="passkey_credential",
        schema=SCHEMA,
    )
    op.drop_table("passkey_credential", schema=SCHEMA)
