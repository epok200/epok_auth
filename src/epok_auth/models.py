from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID

SecurityMetadata = dict[str, str | int | bool | None]


def _empty_security_metadata() -> SecurityMetadata:
    return {}


class UserStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class SecurityEventType(StrEnum):
    ADMIN_CREATED = "admin.created"
    USER_CREATED = "user.created"
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
    failed_login_attempts: int = 0
    locked_until: datetime | None = None
    password_changed_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


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
class AccessClaims:
    user_id: UUID
    session_id: UUID
    family_id: UUID
    issued_at: datetime
    expires_at: datetime
    token_id: str
    authenticated_at: datetime


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


@dataclass(frozen=True, slots=True)
class RequestContext:
    request_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None


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
