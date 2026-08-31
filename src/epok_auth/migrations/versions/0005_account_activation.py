"""Add pending account activation."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_account_activation"
down_revision: str | Sequence[str] | None = "0004_email_links"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "epok_auth"


def upgrade() -> None:
    op.drop_constraint(
        "ck_epok_auth_user_status",
        "user_account",
        type_="check",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        "ck_epok_auth_user_status",
        "user_account",
        "status IN ('pending_activation', 'active', 'disabled')",
        schema=SCHEMA,
    )
    op.drop_constraint(
        "ck_epok_auth_email_link_purpose",
        "email_link",
        type_="check",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        "ck_epok_auth_email_link_purpose",
        "email_link",
        "purpose IN ('activation', 'login', 'password_reset', 'invitation')",
        schema=SCHEMA,
    )


def downgrade() -> None:
    op.execute(sa.text("DELETE FROM epok_auth.email_link WHERE purpose = 'activation'"))
    op.execute(
        sa.text(
            "UPDATE epok_auth.user_account SET status = 'disabled' "
            "WHERE status = 'pending_activation'"
        )
    )
    op.drop_constraint(
        "ck_epok_auth_email_link_purpose",
        "email_link",
        type_="check",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        "ck_epok_auth_email_link_purpose",
        "email_link",
        "purpose IN ('login', 'password_reset', 'invitation')",
        schema=SCHEMA,
    )
    op.drop_constraint(
        "ck_epok_auth_user_status",
        "user_account",
        type_="check",
        schema=SCHEMA,
    )
    op.create_check_constraint(
        "ck_epok_auth_user_status",
        "user_account",
        "status IN ('active', 'disabled')",
        schema=SCHEMA,
    )
