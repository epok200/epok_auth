from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB

SCHEMA = "epok_auth"
metadata = MetaData(schema=SCHEMA)

user_account = Table(
    "user_account",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("email", Text, nullable=False),
    Column("display_name", Text, nullable=False),
    Column("password_hash", Text, nullable=False),
    Column("status", Text, nullable=False, server_default="active"),
    Column("roles", JSONB, nullable=False, server_default=text("'[]'::jsonb")),
    Column("scopes", JSONB, nullable=False, server_default=text("'[]'::jsonb")),
    Column("must_change_password", Boolean, nullable=False, server_default=text("false")),
    Column("failed_login_attempts", Integer, nullable=False, server_default="0"),
    Column("locked_until", DateTime(timezone=True)),
    Column("password_changed_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("now()")),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=text("now()")),
    UniqueConstraint("email", name="uq_epok_auth_user_email"),
    CheckConstraint("email = lower(email)", name="ck_epok_auth_user_email_normalized"),
    CheckConstraint("length(email) BETWEEN 3 AND 320", name="ck_epok_auth_user_email_length"),
    CheckConstraint(
        "length(display_name) BETWEEN 1 AND 200",
        name="ck_epok_auth_user_display_name_length",
    ),
    CheckConstraint("status IN ('active', 'disabled')", name="ck_epok_auth_user_status"),
    CheckConstraint(
        "jsonb_typeof(roles) = 'array' AND jsonb_typeof(scopes) = 'array'",
        name="ck_epok_auth_user_capabilities_arrays",
    ),
    CheckConstraint(
        "failed_login_attempts >= 0",
        name="ck_epok_auth_user_failed_attempts",
    ),
    Index("ix_epok_auth_user_status", "status"),
    Index("ix_epok_auth_user_roles_gin", "roles", postgresql_using="gin"),
)

refresh_session = Table(
    "refresh_session",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column(
        "user_id",
        Uuid(as_uuid=True),
        ForeignKey("user_account.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("family_id", Uuid(as_uuid=True), nullable=False),
    Column("token_hash", Text, nullable=False),
    Column("csrf_hash", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("idle_expires_at", DateTime(timezone=True), nullable=False),
    Column("absolute_expires_at", DateTime(timezone=True), nullable=False),
    Column("authenticated_at", DateTime(timezone=True), nullable=False),
    Column("used_at", DateTime(timezone=True)),
    Column("revoked_at", DateTime(timezone=True)),
    Column(
        "replaced_by_id",
        Uuid(as_uuid=True),
        ForeignKey("refresh_session.id", ondelete="SET NULL"),
    ),
    UniqueConstraint("token_hash", name="uq_epok_auth_refresh_token_hash"),
    UniqueConstraint("replaced_by_id", name="uq_epok_auth_refresh_replacement"),
    CheckConstraint(
        "length(token_hash) = 64 AND length(csrf_hash) = 64",
        name="ck_epok_auth_refresh_hash_lengths",
    ),
    CheckConstraint(
        "idle_expires_at <= absolute_expires_at AND created_at < absolute_expires_at",
        name="ck_epok_auth_refresh_expiry_order",
    ),
    CheckConstraint(
        "(used_at IS NULL AND replaced_by_id IS NULL) OR "
        "(used_at IS NOT NULL AND replaced_by_id IS NOT NULL)",
        name="ck_epok_auth_refresh_replacement_pair",
    ),
    Index("ix_epok_auth_refresh_user", "user_id"),
    Index("ix_epok_auth_refresh_family", "family_id"),
    Index("ix_epok_auth_refresh_expiry", "idle_expires_at", "absolute_expires_at"),
)

security_event = Table(
    "security_event",
    metadata,
    Column("id", BigInteger, Identity(), primary_key=True),
    Column("event_type", Text, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    Column(
        "user_id",
        Uuid(as_uuid=True),
        ForeignKey("user_account.id", ondelete="SET NULL"),
    ),
    Column(
        "session_id",
        Uuid(as_uuid=True),
        ForeignKey("refresh_session.id", ondelete="SET NULL"),
    ),
    Column("request_id", Text),
    Column("ip_address", Text),
    Column("user_agent", Text),
    Column("event_metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    CheckConstraint(
        "length(event_type) BETWEEN 1 AND 100",
        name="ck_epok_auth_event_type_length",
    ),
    Index("ix_epok_auth_event_user_time", "user_id", "occurred_at"),
    Index("ix_epok_auth_event_type_time", "event_type", "occurred_at"),
)

passkey_credential = Table(
    "passkey_credential",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column(
        "user_id",
        Uuid(as_uuid=True),
        ForeignKey("user_account.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("credential_id", LargeBinary, nullable=False),
    Column("public_key", LargeBinary, nullable=False),
    Column("name", Text, nullable=False),
    Column("sign_count", BigInteger, nullable=False, server_default="0"),
    Column("aaguid", Text, nullable=False),
    Column("transports", JSONB, nullable=False, server_default=text("'[]'::jsonb")),
    Column("device_type", Text, nullable=False),
    Column("backed_up", Boolean, nullable=False, server_default=text("false")),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("last_used_at", DateTime(timezone=True)),
    Column("revoked_at", DateTime(timezone=True)),
    UniqueConstraint("credential_id", name="uq_epok_auth_passkey_credential_id"),
    CheckConstraint(
        "octet_length(credential_id) BETWEEN 1 AND 1023",
        name="ck_epok_auth_passkey_credential_id_length",
    ),
    CheckConstraint(
        "octet_length(public_key) BETWEEN 1 AND 16384",
        name="ck_epok_auth_passkey_public_key_length",
    ),
    CheckConstraint("length(name) BETWEEN 1 AND 100", name="ck_epok_auth_passkey_name_length"),
    CheckConstraint("sign_count >= 0", name="ck_epok_auth_passkey_sign_count"),
    CheckConstraint("length(aaguid) BETWEEN 1 AND 36", name="ck_epok_auth_passkey_aaguid"),
    CheckConstraint(
        "jsonb_typeof(transports) = 'array'",
        name="ck_epok_auth_passkey_transports_array",
    ),
    CheckConstraint(
        "device_type IN ('single_device', 'multi_device')",
        name="ck_epok_auth_passkey_device_type",
    ),
    CheckConstraint(
        "NOT backed_up OR device_type = 'multi_device'",
        name="ck_epok_auth_passkey_backup_state",
    ),
    Index("ix_epok_auth_passkey_user", "user_id"),
)

passkey_challenge = Table(
    "passkey_challenge",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("purpose", Text, nullable=False),
    Column("challenge", LargeBinary, nullable=False),
    Column("origin", Text, nullable=False),
    Column(
        "user_id",
        Uuid(as_uuid=True),
        ForeignKey("user_account.id", ondelete="CASCADE"),
    ),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("consumed_at", DateTime(timezone=True)),
    UniqueConstraint("challenge", name="uq_epok_auth_passkey_challenge"),
    CheckConstraint(
        "purpose IN ('registration', 'authentication')",
        name="ck_epok_auth_passkey_challenge_purpose",
    ),
    CheckConstraint(
        "octet_length(challenge) = 32",
        name="ck_epok_auth_passkey_challenge_length",
    ),
    CheckConstraint(
        "length(origin) BETWEEN 1 AND 2048",
        name="ck_epok_auth_passkey_challenge_origin_length",
    ),
    CheckConstraint(
        "created_at < expires_at AND (consumed_at IS NULL OR consumed_at >= created_at)",
        name="ck_epok_auth_passkey_challenge_times",
    ),
    CheckConstraint(
        "(purpose = 'registration' AND user_id IS NOT NULL) OR "
        "(purpose = 'authentication' AND user_id IS NULL)",
        name="ck_epok_auth_passkey_challenge_user",
    ),
    Index("ix_epok_auth_passkey_challenge_expiry", "expires_at"),
)
