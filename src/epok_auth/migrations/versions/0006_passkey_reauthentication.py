"""Bind Passkey reauthentication challenges to a session family."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_passkey_reauthentication"
down_revision: str | Sequence[str] | None = "0005_account_activation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "epok_auth"
TABLE = "passkey_challenge"


def upgrade() -> None:
    op.add_column(
        TABLE,
        sa.Column("family_id", sa.Uuid(), nullable=True),
        schema=SCHEMA,
    )
    _replace_constraints(
        "purpose IN ('registration', 'authentication', 'reauthentication')",
        "(purpose = 'registration' AND user_id IS NOT NULL AND family_id IS NULL) OR "
        "(purpose = 'authentication' AND user_id IS NULL AND family_id IS NULL) OR "
        "(purpose = 'reauthentication' AND user_id IS NOT NULL AND family_id IS NOT NULL)",
    )


def downgrade() -> None:
    op.execute(
        sa.text("DELETE FROM epok_auth.passkey_challenge WHERE purpose = 'reauthentication'")
    )
    _replace_constraints(
        "purpose IN ('registration', 'authentication')",
        "(purpose = 'registration' AND user_id IS NOT NULL) OR "
        "(purpose = 'authentication' AND user_id IS NULL)",
    )
    op.drop_column(TABLE, "family_id", schema=SCHEMA)


def _replace_constraints(purposes: str, binding: str) -> None:
    op.drop_constraint(
        "ck_epok_auth_passkey_challenge_purpose",
        TABLE,
        type_="check",
        schema=SCHEMA,
    )
    op.drop_constraint(
        "ck_epok_auth_passkey_challenge_user",
        TABLE,
        type_="check",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        "ck_epok_auth_passkey_challenge_purpose",
        TABLE,
        purposes,
        schema=SCHEMA,
    )
    op.create_check_constraint(
        "ck_epok_auth_passkey_challenge_user",
        TABLE,
        binding,
        schema=SCHEMA,
    )
