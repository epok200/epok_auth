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
    Column("password_login_enabled", Boolean, nullable=False, server_default=text("true")),
    Column("email_link_login_enabled", Boolean, nullable=False, server_default=text("false")),
    Column("google_auto_link_allowed", Boolean, nullable=False, server_default=text("false")),
    Column("security_version", Integer, nullable=False, server_default="0"),
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
    CheckConstraint("security_version >= 0", name="ck_epok_auth_user_security_version"),
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

external_identity = Table(
    "external_identity",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column(
        "user_id",
        Uuid(as_uuid=True),
        ForeignKey("user_account.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("issuer", Text, nullable=False),
    Column("subject", Text, nullable=False),
    Column("email", Text),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("last_login_at", DateTime(timezone=True)),
    UniqueConstraint("issuer", "subject", name="uq_epok_auth_external_identity_subject"),
    UniqueConstraint("user_id", "issuer", name="uq_epok_auth_external_identity_user_issuer"),
    CheckConstraint(
        "length(issuer) BETWEEN 1 AND 255 AND length(subject) BETWEEN 1 AND 255",
        name="ck_epok_auth_external_identity_keys",
    ),
    CheckConstraint(
        "email IS NULL OR length(email) BETWEEN 3 AND 320",
        name="ck_epok_auth_external_identity_email",
    ),
    CheckConstraint(
        "last_login_at IS NULL OR last_login_at >= created_at",
        name="ck_epok_auth_external_identity_times",
    ),
    Index("ix_epok_auth_external_identity_user", "user_id"),
)

google_challenge = Table(
    "google_challenge",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("purpose", Text, nullable=False),
    Column("nonce", Text, nullable=False),
    Column("origin", Text, nullable=False),
    Column("client_id", Text, nullable=False),
    Column(
        "user_id",
        Uuid(as_uuid=True),
        ForeignKey("user_account.id", ondelete="CASCADE"),
    ),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("consumed_at", DateTime(timezone=True)),
    UniqueConstraint("nonce", name="uq_epok_auth_google_challenge_nonce"),
    CheckConstraint(
        "purpose IN ('login', 'link')",
        name="ck_epok_auth_google_challenge_purpose",
    ),
    CheckConstraint(
        "length(nonce) BETWEEN 32 AND 255",
        name="ck_epok_auth_google_challenge_nonce",
    ),
    CheckConstraint(
        "length(origin) BETWEEN 1 AND 2048 AND length(client_id) BETWEEN 20 AND 255",
        name="ck_epok_auth_google_challenge_context",
    ),
    CheckConstraint(
        "created_at < expires_at AND (consumed_at IS NULL OR consumed_at >= created_at)",
        name="ck_epok_auth_google_challenge_times",
    ),
    CheckConstraint(
        "(purpose = 'login' AND user_id IS NULL) OR (purpose = 'link' AND user_id IS NOT NULL)",
        name="ck_epok_auth_google_challenge_user",
    ),
    Index("ix_epok_auth_google_challenge_expiry", "expires_at"),
)

email_link = Table(
    "email_link",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column(
        "user_id",
        Uuid(as_uuid=True),
        ForeignKey("user_account.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("purpose", Text, nullable=False),
    Column("generation", Integer, nullable=False),
    Column("token_hash", Text, nullable=False),
    Column("recipient_hash", Text, nullable=False),
    Column("browser_hash", Text),
    Column("security_version", Integer, nullable=False),
    Column("state", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("delivered_at", DateTime(timezone=True)),
    Column("consumed_at", DateTime(timezone=True)),
    Column("revoked_at", DateTime(timezone=True)),
    UniqueConstraint("token_hash", name="uq_epok_auth_email_link_token_hash"),
    UniqueConstraint(
        "user_id",
        "purpose",
        "generation",
        name="uq_epok_auth_email_link_generation",
    ),
    CheckConstraint(
        "purpose IN ('login', 'password_reset', 'invitation')",
        name="ck_epok_auth_email_link_purpose",
    ),
    CheckConstraint(
        "state IN ('pending', 'active', 'failed', 'consumed', 'revoked')",
        name="ck_epok_auth_email_link_state",
    ),
    CheckConstraint(
        "length(token_hash) = 64 AND length(recipient_hash) = 64 "
        "AND (browser_hash IS NULL OR length(browser_hash) = 64)",
        name="ck_epok_auth_email_link_hashes",
    ),
    CheckConstraint(
        "(purpose = 'login' AND browser_hash IS NOT NULL) "
        "OR (purpose <> 'login' AND browser_hash IS NULL)",
        name="ck_epok_auth_email_link_browser",
    ),
    CheckConstraint(
        "generation > 0 AND security_version >= 0",
        name="ck_epok_auth_email_link_versions",
    ),
    CheckConstraint(
        "created_at < expires_at "
        "AND (delivered_at IS NULL OR delivered_at >= created_at) "
        "AND (consumed_at IS NULL OR consumed_at >= created_at) "
        "AND (revoked_at IS NULL OR revoked_at >= created_at)",
        name="ck_epok_auth_email_link_times",
    ),
    CheckConstraint(
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
    Index("ix_epok_auth_email_link_user_purpose", "user_id", "purpose", "generation"),
    Index("ix_epok_auth_email_link_state_expiry", "state", "expires_at"),
    Index("ix_epok_auth_email_link_created", "created_at"),
)
