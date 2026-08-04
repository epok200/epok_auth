from __future__ import annotations

import asyncio
from dataclasses import replace
from uuid import uuid4

import pytest

from epok_auth.errors import AuthError, AuthErrorCode
from epok_auth.models import RequestContext, SecurityEventType, UserStatus, UserUpdate
from epok_auth.service import AuthService, normalize_capabilities, normalize_display_name, normalize_email
from epok_auth.testing import MemoryAuthStore
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, USER_EMAIL


@pytest.mark.asyncio
async def test_create_initial_admin_once(
    service: AuthService,
    store: MemoryAuthStore,
) -> None:
    admin = await service.create_admin(
        email=f"  {ADMIN_EMAIL.upper()}  ",
        display_name="  Primary   Administrator ",
        password=ADMIN_PASSWORD,
        context=RequestContext(request_id="request-1", ip_address="127.0.0.1"),
    )
    assert admin.email == ADMIN_EMAIL
    assert admin.display_name == "Primary Administrator"
    assert admin.roles == ("admin",)
    assert admin.scopes == ("auth:admin",)
    assert admin.password_hash.startswith("$argon2")
    assert store.events[-1].event_type is SecurityEventType.ADMIN_CREATED
    assert store.events[-1].request_id == "request-1"

    with pytest.raises(AuthError) as captured:
        await service.create_admin(
            email="other@example.com",
            display_name="Other",
            password=ADMIN_PASSWORD,
        )
    assert captured.value.code is AuthErrorCode.ADMIN_EXISTS


@pytest.mark.asyncio
async def test_create_admin_is_transactionally_singleton(
    service: AuthService,
) -> None:
    async def create(email: str) -> str:
        try:
            await service.create_admin(
                email=email,
                display_name=email,
                password=ADMIN_PASSWORD,
            )
        except AuthError as error:
            return error.code.value
        return "created"

    outcomes = await asyncio.gather(create("one@example.com"), create("two@example.com"))
    assert outcomes.count("created") == 1
    assert outcomes.count(AuthErrorCode.ADMIN_EXISTS.value) == 1


@pytest.mark.asyncio
async def test_administrator_can_provision_user_with_one_time_password(
    service: AuthService,
    store: MemoryAuthStore,
) -> None:
    result = await service.create_user(
        email=USER_EMAIL,
        display_name="Laboratory Analyst",
        roles=("viewer", "editor", "viewer"),
        scopes=("catalog:read", "catalog:write"),
    )
    assert result.user.email == USER_EMAIL
    assert result.user.roles == ("editor", "viewer")
    assert result.user.must_change_password is True
    assert len(result.temporary_password) >= 32
    assert result.temporary_password not in repr(result)
    assert result.user.password_hash != result.temporary_password
    assert store.events[-1].event_type is SecurityEventType.USER_CREATED

    with pytest.raises(AuthError) as captured:
        await service.create_user(email=USER_EMAIL, display_name="Duplicate")
    assert captured.value.code is AuthErrorCode.USER_EXISTS


@pytest.mark.asyncio
async def test_list_get_and_update_users(service: AuthService) -> None:
    admin = await service.create_admin(
        email=ADMIN_EMAIL,
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    provisioned = await service.create_user(email=USER_EMAIL, display_name="Analyst")
    users = await service.list_users(limit=10, offset=0)
    assert {item.id for item in users} == {admin.id, provisioned.user.id}
    assert await service.get_user(provisioned.user.id) == provisioned.user

    updated = await service.update_user(
        provisioned.user.id,
        UserUpdate(
            display_name="Senior Analyst",
            roles=("editor",),
            scopes=("catalog:read", "catalog:write"),
        ),
    )
    assert updated.display_name == "Senior Analyst"
    assert updated.roles == ("editor",)
    assert updated.scopes == ("catalog:read", "catalog:write")

    with pytest.raises(AuthError) as missing:
        await service.get_user(uuid4())
    assert missing.value.code is AuthErrorCode.USER_NOT_FOUND
    with pytest.raises(AuthError):
        await service.update_user(uuid4(), UserUpdate(display_name="Missing"))


@pytest.mark.asyncio
async def test_pagination_is_validated(service: AuthService) -> None:
    with pytest.raises(AuthError) as captured:
        await service.list_users(limit=0)
    assert captured.value.code is AuthErrorCode.INPUT_INVALID
    with pytest.raises(AuthError):
        await service.list_users(limit=501)
    with pytest.raises(AuthError):
        await service.list_users(offset=-1)


@pytest.mark.asyncio
async def test_disabling_user_revokes_existing_sessions(
    service: AuthService,
) -> None:
    provisioned = await service.create_user(email=USER_EMAIL, display_name="Analyst")
    bundle = await service.login(USER_EMAIL, provisioned.temporary_password)
    disabled = await service.update_user(
        provisioned.user.id,
        UserUpdate(status=UserStatus.DISABLED),
    )
    assert disabled.status is UserStatus.DISABLED
    with pytest.raises(AuthError) as captured:
        await service.authenticate(bundle.access_token)
    assert captured.value.code is AuthErrorCode.INVALID_TOKEN

    enabled = await service.update_user(
        provisioned.user.id,
        UserUpdate(status=UserStatus.ACTIVE),
    )
    assert enabled.status is UserStatus.ACTIVE


@pytest.mark.asyncio
async def test_cannot_remove_or_disable_last_active_admin(service: AuthService) -> None:
    admin = await service.create_admin(
        email=ADMIN_EMAIL,
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    with pytest.raises(AuthError) as disabled:
        await service.update_user(admin.id, UserUpdate(status=UserStatus.DISABLED))
    assert disabled.value.code is AuthErrorCode.LAST_ADMIN_REQUIRED

    with pytest.raises(AuthError) as demoted:
        await service.update_user(admin.id, UserUpdate(roles=("user",)))
    assert demoted.value.code is AuthErrorCode.LAST_ADMIN_REQUIRED

    second = await service.create_user(
        email="second-admin@example.com",
        display_name="Second Admin",
        roles=("admin",),
    )
    changed = await service.update_user(admin.id, UserUpdate(roles=("user",)))
    assert changed.roles == ("user",)
    assert second.user.roles == ("admin",)


@pytest.mark.asyncio
async def test_password_reset_revokes_sessions_and_returns_secret_once(
    service: AuthService,
) -> None:
    result = await service.create_user(email=USER_EMAIL, display_name="Analyst")
    bundle = await service.login(USER_EMAIL, result.temporary_password)
    reset = await service.reset_password(result.user.id)
    assert reset.user.must_change_password
    assert reset.temporary_password != result.temporary_password
    with pytest.raises(AuthError):
        await service.authenticate(bundle.access_token)
    with pytest.raises(AuthError):
        await service.login(USER_EMAIL, result.temporary_password)
    assert (await service.login(USER_EMAIL, reset.temporary_password)).principal.user_id == result.user.id


@pytest.mark.asyncio
async def test_manual_session_revocation_is_audited(service: AuthService, store: MemoryAuthStore) -> None:
    admin = await service.create_admin(
        email=ADMIN_EMAIL,
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    await service.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    count = await service.revoke_user_sessions(
        admin.id,
        context=RequestContext(request_id="x" * 500, user_agent="u" * 900),
    )
    assert count == 1
    event = store.events[-1]
    assert event.event_type is SecurityEventType.SESSIONS_REVOKED
    assert event.metadata == {"count": 1}
    assert len(event.request_id or "") == 200
    assert len(event.user_agent or "") == 500

    with pytest.raises(AuthError):
        await service.revoke_user_sessions(uuid4())


def test_identity_and_capability_normalizers() -> None:
    assert normalize_email(" User@Example.COM ") == "user@example.com"
    assert normalize_display_name("  Ana   María  ") == "Ana María"
    assert normalize_capabilities(("Write", "read", "write"), maximum=5) == ("read", "write")

    for invalid in ("", "bad capability", ":starts-wrong", "x" * 101):
        with pytest.raises(AuthError):
            normalize_capabilities((invalid,), maximum=5)
    with pytest.raises(AuthError):
        normalize_capabilities(tuple(str(i) for i in range(6)), maximum=5)
    with pytest.raises(AuthError):
        normalize_display_name("\n")
    with pytest.raises(AuthError):
        normalize_email("not-an-email")
