from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Self
from uuid import UUID

SecurityMetadata = dict[str, str | int | bool | None]


def _empty_security_metadata() -> SecurityMetadata:
    return {}


class UserStatus(StrEnum):
    PENDING_ACTIVATION = "pending_activation"
    ACTIVE = "active"
    DISABLED = "disabled"


class SecurityEventType(StrEnum):
    ADMIN_CREATED = "admin.created"
    USER_CREATED = "user.created"
    ACCOUNT_ACTIVATED = "account.activated"
    USER_UPDATED = "user.updated"
    USER_DISABLED = "user.disabled"
    USER_ENABLED = "user.enabled"
    PASSWORD_RESET = "password.reset"
    PASSWORD_CHANGED = "password.changed"
    LOGIN_SUCCEEDED = "login.succeeded"
    LOGIN_FAILED = "login.failed"
    ACCOUNT_LOCKED = "account.locked"
    SESSION_CREATED = "session.created"
    REFRESH_ROTATED = "refresh.rotated"
    REFRESH_CONFLICT = "refresh.concurrent_conflict"
    REFRESH_REUSE_DETECTED = "refresh.reuse_detected"
    LOGOUT = "session.logout"
    SESSIONS_REVOKED = "sessions.revoked"
    PASSKEY_REGISTERED = "passkey.registered"
    PASSKEY_REGISTRATION_FAILED = "passkey.registration_failed"
    PASSKEY_LOGIN_SUCCEEDED = "passkey.login_succeeded"
    PASSKEY_LOGIN_FAILED = "passkey.login_failed"
    PASSKEY_REVOKED = "passkey.revoked"
    GOOGLE_ACCOUNT_CREATED = "google.account_created"
    GOOGLE_IDENTITY_LINKED = "google.identity_linked"
    GOOGLE_LINK_FAILED = "google.link_failed"
    GOOGLE_LOGIN_SUCCEEDED = "google.login_succeeded"
    GOOGLE_LOGIN_FAILED = "google.login_failed"
    GOOGLE_RECOVERY_COMPLETED = "google.recovery_completed"
    EMAIL_LINK_ISSUED = "email_link.issued"
    EMAIL_LINK_DELIVERED = "email_link.delivered"
    EMAIL_LINK_DELIVERY_FAILED = "email_link.delivery_failed"
    EMAIL_NOTICE_DELIVERY_FAILED = "email_notice.delivery_failed"
    EMAIL_LINK_LOGIN_SUCCEEDED = "email_link.login_succeeded"
    EMAIL_LINK_LOGIN_FAILED = "email_link.login_failed"
    PASSWORD_RECOVERY_COMPLETED = "password.recovery_completed"
    INVITATION_ACTIVATED = "invitation.activated"


@dataclass(frozen=True, slots=True)
class UserAccount:
    id: UUID
    email: str
    display_name: str
    password_hash: str = field(repr=False)
    status: UserStatus = UserStatus.ACTIVE
    roles: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    must_change_password: bool = False
    password_login_enabled: bool = True
    email_link_login_enabled: bool = False
    google_auto_link_allowed: bool = False
    security_version: int = 0
    failed_login_attempts: int = 0
    locked_until: datetime | None = None
    password_changed_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def can_authenticate(self, now: datetime) -> bool:
        return self.status is UserStatus.ACTIVE and not (
            self.locked_until and self.locked_until > now
        )

    def advance_security_version(self, at: datetime) -> Self:
        return replace(
            self,
            security_version=self.security_version + 1,
            updated_at=at,
        )

    def require_password_change(self, password_hash: str, at: datetime) -> Self:
        return replace(
            self._replace_password(password_hash, at),
            must_change_password=True,
            password_login_enabled=True,
        )

    def activate_password(self, password_hash: str, at: datetime) -> Self:
        return replace(
            self._replace_password(password_hash, at),
            must_change_password=False,
            password_login_enabled=True,
        )

    def activate_account(self, password_hash: str, at: datetime) -> Self:
        if self.status is not UserStatus.PENDING_ACTIVATION:
            raise ValueError("only a pending account can be activated")
        return replace(
            self.activate_password(password_hash, at),
            status=UserStatus.ACTIVE,
        )

    def disable_password(self, password_hash: str, at: datetime) -> Self:
        return replace(
            self._replace_password(password_hash, at),
            must_change_password=False,
            password_login_enabled=False,
        )

    def activate_email_link_login(self, password_hash: str, at: datetime) -> Self:
        return replace(
            self.disable_password(password_hash, at),
            email_link_login_enabled=True,
        )

    def _replace_password(self, password_hash: str, at: datetime) -> Self:
        return replace(
            self.advance_security_version(at),
            password_hash=password_hash,
            google_auto_link_allowed=False,
            failed_login_attempts=0,
            locked_until=None,
            password_changed_at=at,
        )


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: UUID
    session_id: UUID
    family_id: UUID
    email: str
    display_name: str
    roles: tuple[str, ...]
    scopes: tuple[str, ...]
    must_change_password: bool
    authenticated_at: datetime

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


@dataclass(frozen=True, slots=True)
class AccessClaims:
    user_id: UUID
    session_id: UUID
    family_id: UUID
    issued_at: datetime
    expires_at: datetime
    token_id: str
    authenticated_at: datetime


@dataclass(frozen=True, slots=True)
class RefreshSession:
    id: UUID
    user_id: UUID
    family_id: UUID
    token_hash: str = field(repr=False)
    csrf_hash: str = field(repr=False)
    created_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    authenticated_at: datetime
    used_at: datetime | None = None
    revoked_at: datetime | None = None
    replaced_by_id: UUID | None = None

    def is_active(self, now: datetime) -> bool:
        return (
            self.revoked_at is None
            and self.idle_expires_at > now
            and self.absolute_expires_at > now
        )

    def is_valid_for(self, subject: Principal | AccessClaims, now: datetime) -> bool:
        authentication_matches = (
            abs((self.authenticated_at - subject.authenticated_at).total_seconds()) <= 1
        )
        return (
            self.is_active(now)
            and self.id == subject.session_id
            and self.user_id == subject.user_id
            and self.family_id == subject.family_id
            and authentication_matches
        )


@dataclass(frozen=True, slots=True)
class SessionBundle:
    access_token: str = field(repr=False)
    access_expires_in: int
    refresh_token: str = field(repr=False)
    csrf_token: str = field(repr=False)
    refresh_idle_expires_at: datetime
    refresh_absolute_expires_at: datetime
    principal: Principal


@dataclass(frozen=True, slots=True)
class RequestContext:
    request_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    event_type: SecurityEventType
    occurred_at: datetime
    user_id: UUID | None = None
    session_id: UUID | None = None
    request_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    metadata: SecurityMetadata = field(default_factory=_empty_security_metadata)

    @classmethod
    def from_request(
        cls,
        event_type: SecurityEventType,
        occurred_at: datetime,
        *,
        context: RequestContext,
        user_id: UUID | None = None,
        session_id: UUID | None = None,
        metadata: SecurityMetadata | None = None,
    ) -> Self:
        return cls(
            event_type=event_type,
            occurred_at=occurred_at,
            user_id=user_id,
            session_id=session_id,
            request_id=_bounded(context.request_id, 200),
            ip_address=_bounded(context.ip_address, 64),
            user_agent=_bounded(context.user_agent, 500),
            metadata=dict(metadata) if metadata is not None else {},
        )


@dataclass(frozen=True, slots=True)
class ProvisionedUser:
    user: UserAccount
    temporary_password: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class UserUpdate:
    display_name: str | None = None
    status: UserStatus | None = None
    roles: tuple[str, ...] | None = None
    scopes: tuple[str, ...] | None = None
    email_link_login_enabled: bool | None = None
    google_auto_link_allowed: bool | None = None


def _bounded(value: str | None, maximum: int) -> str | None:
    return value[:maximum] if value is not None else None
