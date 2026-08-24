from datetime import datetime
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from epok_auth.models import Principal, ProvisionedUser, SessionBundle, UserAccount, UserStatus

ShortText = Annotated[str, StringConstraints(min_length=1, max_length=200)]
Capability = Annotated[str, StringConstraints(min_length=1, max_length=100)]
Credential = Annotated[str, StringConstraints(min_length=1, max_length=4096)]
EmailInput = Annotated[str, StringConstraints(min_length=3, max_length=320)]


class StrictSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(StrictSchema):
    email: EmailInput
    password: Credential


class ChangePasswordRequest(StrictSchema):
    current_password: Credential
    new_password: Credential


class CreateUserRequest(StrictSchema):
    email: EmailInput
    display_name: ShortText
    roles: list[Capability] | None = Field(default=None, max_length=256)
    scopes: list[Capability] = Field(default_factory=list, max_length=2048)
    google_auto_link_allowed: bool = False


class UpdateUserRequest(StrictSchema):
    display_name: ShortText | None = None
    status: UserStatus | None = None
    roles: list[Capability] | None = Field(default=None, max_length=256)
    scopes: list[Capability] | None = Field(default=None, max_length=2048)
    google_auto_link_allowed: bool | None = None


class ErrorResponse(BaseModel):
    code: str
    detail: str
    request_id: str | None = None


class PrincipalResponse(BaseModel):
    id: UUID
    email: str
    display_name: str
    roles: list[str]
    scopes: list[str]
    must_change_password: bool
    authenticated_at: datetime

    @classmethod
    def from_principal(cls, principal: Principal) -> Self:
        return cls(
            id=principal.user_id,
            email=principal.email,
            display_name=principal.display_name,
            roles=list(principal.roles),
            scopes=list(principal.scopes),
            must_change_password=principal.must_change_password,
            authenticated_at=principal.authenticated_at,
        )


class UserResponse(BaseModel):
    id: UUID
    email: str
    display_name: str
    status: UserStatus
    roles: list[str]
    scopes: list[str]
    must_change_password: bool
    password_login_enabled: bool
    google_auto_link_allowed: bool
    failed_login_attempts: int
    locked_until: datetime | None
    password_changed_at: datetime | None
    created_at: datetime | None
    updated_at: datetime | None

    @classmethod
    def from_user(cls, user: UserAccount) -> Self:
        return cls(
            id=user.id,
            email=user.email,
            display_name=user.display_name,
            status=user.status,
            roles=list(user.roles),
            scopes=list(user.scopes),
            must_change_password=user.must_change_password,
            password_login_enabled=user.password_login_enabled,
            google_auto_link_allowed=user.google_auto_link_allowed,
            failed_login_attempts=user.failed_login_attempts,
            locked_until=user.locked_until,
            password_changed_at=user.password_changed_at,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )


class SessionResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    csrf_token: str
    refresh_idle_expires_at: datetime
    refresh_absolute_expires_at: datetime
    user: PrincipalResponse

    @classmethod
    def from_bundle(cls, bundle: SessionBundle) -> Self:
        return cls(
            access_token=bundle.access_token,
            expires_in=bundle.access_expires_in,
            csrf_token=bundle.csrf_token,
            refresh_idle_expires_at=bundle.refresh_idle_expires_at,
            refresh_absolute_expires_at=bundle.refresh_absolute_expires_at,
            user=PrincipalResponse.from_principal(bundle.principal),
        )


class ProvisionedUserResponse(BaseModel):
    user: UserResponse
    temporary_password: str

    @classmethod
    def from_result(cls, result: ProvisionedUser) -> Self:
        return cls(
            user=UserResponse.from_user(result.user),
            temporary_password=result.temporary_password,
        )


class UserListResponse(BaseModel):
    items: list[UserResponse]
    limit: int
    offset: int


class RevocationResponse(BaseModel):
    revoked_sessions: int
