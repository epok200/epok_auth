import asyncio
from dataclasses import replace
from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from epok_auth.errors import AuthError, AuthErrorCode
from epok_auth.models import SecurityEventType, UserStatus
from epok_auth.service import AuthService, canonical_origin
from epok_auth.testing import MemoryAuthStore
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, NEW_PASSWORD, MutableClock


async def create_admin_and_login(service: AuthService):
    await service.create_admin(
        email=ADMIN_EMAIL,
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    return await service.login(ADMIN_EMAIL, ADMIN_PASSWORD)


@pytest.mark.asyncio
async def test_login_access_and_authoritative_revocation(
    service: AuthService,
    store: MemoryAuthStore,
) -> None:
    bundle = await create_admin_and_login(service)
    principal = await service.authenticate(bundle.access_token)
    assert principal.email == ADMIN_EMAIL
    assert principal.session_id == bundle.principal.session_id
    await service.logout(
        bundle.refresh_token,
        bundle.csrf_token,
        bundle.csrf_token,
        origin="http://localhost:3000",
    )
    with pytest.raises(AuthError) as captured:
        await service.authenticate(bundle.access_token)
    assert captured.value.code is AuthErrorCode.INVALID_TOKEN
    assert SecurityEventType.LOGIN_SUCCEEDED in {event.event_type for event in store.events}
    assert SecurityEventType.LOGOUT in {event.event_type for event in store.events}


@pytest.mark.asyncio
async def test_login_failure_is_uniform_and_locks_account(
    service: AuthService,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    await service.create_admin(
        email=ADMIN_EMAIL,
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    details: set[tuple[str, str, int]] = set()
    for email, password in (
        ("missing@example.com", "wrong password value"),
        (ADMIN_EMAIL, "wrong password value"),
        (ADMIN_EMAIL, "wrong password value"),
    ):
        with pytest.raises(AuthError) as captured:
            await service.login(email, password)
        details.add((captured.value.code.value, captured.value.detail, captured.value.status_code))
    assert details == {
        (AuthErrorCode.INVALID_CREDENTIALS.value, "The email or password is not valid.", 401)
    }

    # Third failure reaches the configured threshold.
    with pytest.raises(AuthError):
        await service.login(ADMIN_EMAIL, "wrong password value")
    user = next(iter(store.users.values()))
    assert user.failed_login_attempts == 3
    assert user.locked_until == clock.value + timedelta(seconds=120)
    with pytest.raises(AuthError):
        await service.login(ADMIN_EMAIL, ADMIN_PASSWORD)

    clock.advance(seconds=121)
    with pytest.raises(AuthError):
        await service.login(ADMIN_EMAIL, "wrong password value")
    user = next(iter(store.users.values()))
    assert user.failed_login_attempts == 1
    assert user.locked_until is None
    assert SecurityEventType.ACCOUNT_LOCKED in {event.event_type for event in store.events}


@pytest.mark.asyncio
async def test_disabled_account_uses_same_login_response(service: AuthService) -> None:
    admin = await service.create_admin(
        email=ADMIN_EMAIL,
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    # Insert a second admin before disabling the first to preserve the invariant.
    await service.create_user(email="backup@example.com", display_name="Backup", roles=("admin",))
    await service.update_user(admin.id, replace_user_status(UserStatus.DISABLED))
    with pytest.raises(AuthError) as captured:
        await service.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    assert captured.value.code is AuthErrorCode.INVALID_CREDENTIALS


def replace_user_status(status: UserStatus):
    from epok_auth.models import UserUpdate

    return UserUpdate(status=status)


@pytest.mark.asyncio
async def test_refresh_rotates_and_preserves_absolute_deadline(
    service: AuthService,
    clock: MutableClock,
) -> None:
    first = await create_admin_and_login(service)
    clock.advance(seconds=60)
    second = await service.refresh(
        first.refresh_token,
        first.csrf_token,
        first.csrf_token,
        origin="HTTP://LOCALHOST:3000/",
    )
    assert second.refresh_token != first.refresh_token
    assert second.access_token != first.access_token
    assert second.principal.family_id == first.principal.family_id
    assert second.refresh_absolute_expires_at == first.refresh_absolute_expires_at
    assert second.refresh_idle_expires_at > first.refresh_idle_expires_at


@pytest.mark.asyncio
async def test_refresh_rejects_unknown_token(service: AuthService) -> None:
    with pytest.raises(AuthError) as captured:
        await service.refresh(
            "unknown-refresh-token",
            "matching-csrf",
            "matching-csrf",
            origin="http://localhost:3000",
        )

    assert captured.value.code is AuthErrorCode.INVALID_TOKEN


@pytest.mark.asyncio
async def test_refresh_rejects_revoked_session(
    service: AuthService,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    bundle = await create_admin_and_login(service)
    session_id = bundle.principal.session_id
    store.sessions[session_id] = replace(store.sessions[session_id], revoked_at=clock.value)

    with pytest.raises(AuthError) as captured:
        await service.refresh(
            bundle.refresh_token,
            bundle.csrf_token,
            bundle.csrf_token,
            origin="http://localhost:3000",
        )

    assert captured.value.code is AuthErrorCode.INVALID_TOKEN


@pytest.mark.asyncio
async def test_refresh_reuse_revokes_entire_family(service: AuthService) -> None:
    first = await create_admin_and_login(service)
    second = await service.refresh(
        first.refresh_token,
        first.csrf_token,
        first.csrf_token,
        origin="http://localhost:3000",
    )
    with pytest.raises(AuthError) as reused:
        await service.refresh(
            first.refresh_token,
            first.csrf_token,
            first.csrf_token,
            origin="http://localhost:3000",
        )
    assert reused.value.code is AuthErrorCode.INVALID_TOKEN
    with pytest.raises(AuthError):
        await service.authenticate(second.access_token)


@pytest.mark.asyncio
async def test_concurrent_refresh_has_strict_fail_closed_semantics(service: AuthService) -> None:
    first = await create_admin_and_login(service)

    async def rotate():
        try:
            return await service.refresh(
                first.refresh_token,
                first.csrf_token,
                first.csrf_token,
                origin="http://localhost:3000",
            )
        except AuthError as error:
            return error

    outcomes = await asyncio.gather(rotate(), rotate())
    successes = [item for item in outcomes if not isinstance(item, AuthError)]
    failures = [item for item in outcomes if isinstance(item, AuthError)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert failures[0].code is AuthErrorCode.INVALID_TOKEN
    # Reuse detection revokes the family even if another concurrent request got a token.
    with pytest.raises(AuthError):
        await service.authenticate(successes[0].access_token)


@pytest.mark.asyncio
async def test_refresh_rejects_csrf_and_origin_without_consuming_token(
    service: AuthService,
) -> None:
    first = await create_admin_and_login(service)
    for cookie, header, origin, expected in (
        (first.csrf_token, "wrong", "http://localhost:3000", AuthErrorCode.INVALID_CSRF),
        (first.csrf_token, first.csrf_token, None, AuthErrorCode.INVALID_ORIGIN),
        (
            first.csrf_token,
            first.csrf_token,
            "https://evil.example",
            AuthErrorCode.INVALID_ORIGIN,
        ),
    ):
        with pytest.raises(AuthError) as captured:
            await service.refresh(
                first.refresh_token,
                cookie,
                header,
                origin=origin,
            )
        assert captured.value.code is expected

    valid = await service.refresh(
        first.refresh_token,
        first.csrf_token,
        first.csrf_token,
        origin="http://localhost:3000",
    )
    assert valid.principal.user_id == first.principal.user_id


@pytest.mark.asyncio
async def test_refresh_rejects_csrf_that_does_not_match_stored_session(
    service: AuthService,
) -> None:
    bundle = await create_admin_and_login(service)

    with pytest.raises(AuthError) as captured:
        await service.refresh(
            bundle.refresh_token,
            "attacker-csrf",
            "attacker-csrf",
            origin="http://localhost:3000",
        )

    assert captured.value.code is AuthErrorCode.INVALID_CSRF


@pytest.mark.asyncio
async def test_refresh_revokes_family_when_account_becomes_inactive(
    service: AuthService,
    store: MemoryAuthStore,
) -> None:
    bundle = await create_admin_and_login(service)
    user_id = bundle.principal.user_id
    store.users[user_id] = replace(store.users[user_id], status=UserStatus.DISABLED)

    with pytest.raises(AuthError) as captured:
        await service.refresh(
            bundle.refresh_token,
            bundle.csrf_token,
            bundle.csrf_token,
            origin="http://localhost:3000",
        )

    assert captured.value.code is AuthErrorCode.INVALID_TOKEN
    assert all(session.revoked_at is not None for session in store.sessions.values())


@pytest.mark.asyncio
async def test_idle_and_absolute_expiry_are_enforced(
    service: AuthService,
    clock: MutableClock,
) -> None:
    first = await create_admin_and_login(service)
    clock.advance(seconds=901)
    with pytest.raises(AuthError):
        await service.authenticate(first.access_token)
    with pytest.raises(AuthError):
        await service.refresh(
            first.refresh_token,
            first.csrf_token,
            first.csrf_token,
            origin="http://localhost:3000",
        )

    # A fresh family can refresh while idle-active but never extends its absolute deadline.
    second = await service.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    absolute = second.refresh_absolute_expires_at
    clock.advance(seconds=850)
    third = await service.refresh(
        second.refresh_token,
        second.csrf_token,
        second.csrf_token,
        origin="http://localhost:3000",
    )
    assert third.refresh_absolute_expires_at == absolute
    clock.value = absolute + timedelta(seconds=1)
    with pytest.raises(AuthError):
        await service.refresh(
            third.refresh_token,
            third.csrf_token,
            third.csrf_token,
            origin="http://localhost:3000",
        )


@pytest.mark.asyncio
async def test_logout_is_idempotent_and_csrf_protected(service: AuthService) -> None:
    bundle = await create_admin_and_login(service)
    assert await service.logout(None, None, None, origin="http://localhost:3000") == 0
    with pytest.raises(AuthError) as csrf:
        await service.logout(
            bundle.refresh_token,
            bundle.csrf_token,
            "wrong",
            origin="http://localhost:3000",
        )
    assert csrf.value.code is AuthErrorCode.INVALID_CSRF
    assert (
        await service.logout(
            bundle.refresh_token,
            bundle.csrf_token,
            bundle.csrf_token,
            origin="http://localhost:3000",
        )
        == 1
    )
    assert (
        await service.logout(
            bundle.refresh_token,
            bundle.csrf_token,
            bundle.csrf_token,
            origin="http://localhost:3000",
        )
        == 0
    )


@pytest.mark.asyncio
async def test_logout_rejects_csrf_that_does_not_match_stored_session(
    service: AuthService,
) -> None:
    bundle = await create_admin_and_login(service)

    with pytest.raises(AuthError) as captured:
        await service.logout(
            bundle.refresh_token,
            "attacker-csrf",
            "attacker-csrf",
            origin="http://localhost:3000",
        )

    assert captured.value.code is AuthErrorCode.INVALID_CSRF


@pytest.mark.asyncio
async def test_change_password_revokes_old_family_and_starts_fresh_session(
    service: AuthService,
    store: MemoryAuthStore,
) -> None:
    old = await create_admin_and_login(service)
    initial_version = store.users[old.principal.user_id].security_version
    with pytest.raises(AuthError):
        await service.change_password(old.principal, "wrong password value", NEW_PASSWORD)
    with pytest.raises(AuthError) as same:
        await service.change_password(old.principal, ADMIN_PASSWORD, ADMIN_PASSWORD)
    assert same.value.code is AuthErrorCode.PASSWORD_INVALID

    new = await service.change_password(old.principal, ADMIN_PASSWORD, NEW_PASSWORD)
    assert store.users[old.principal.user_id].security_version == initial_version + 1
    assert new.principal.family_id != old.principal.family_id
    assert new.principal.must_change_password is False
    with pytest.raises(AuthError):
        await service.authenticate(old.access_token)
    with pytest.raises(AuthError):
        await service.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    assert (
        await service.login(ADMIN_EMAIL, NEW_PASSWORD)
    ).principal.user_id == old.principal.user_id


@pytest.mark.asyncio
async def test_change_password_rejects_principal_from_another_session(
    service: AuthService,
) -> None:
    bundle = await create_admin_and_login(service)
    mismatched = replace(bundle.principal, family_id=uuid4())

    with pytest.raises(AuthError) as captured:
        await service.change_password(mismatched, ADMIN_PASSWORD, NEW_PASSWORD)

    assert captured.value.code is AuthErrorCode.INVALID_TOKEN


@pytest.mark.asyncio
async def test_required_password_change_blocks_application_dependency_but_not_me(
    service: AuthService,
) -> None:
    provisioned = await service.create_user(email="new@example.com", display_name="New User")
    bundle = await service.login("new@example.com", provisioned.temporary_password)
    assert bundle.principal.must_change_password is True


@pytest.mark.asyncio
async def test_roles_scopes_and_recent_authentication(
    service: AuthService,
    clock: MutableClock,
) -> None:
    bundle = await create_admin_and_login(service)
    service.require_roles(bundle.principal, "admin")
    service.require_scopes(bundle.principal, "auth:admin")
    with pytest.raises(AuthError) as role:
        service.require_roles(bundle.principal, "editor")
    assert role.value.code is AuthErrorCode.FORBIDDEN
    with pytest.raises(AuthError):
        service.require_scopes(bundle.principal, "catalog:write")

    service.require_recent_authentication(bundle.principal, max_age_seconds=300)
    clock.advance(seconds=301)
    with pytest.raises(AuthError):
        service.require_recent_authentication(bundle.principal, max_age_seconds=300)
    with pytest.raises(ValueError):
        service.require_recent_authentication(bundle.principal, max_age_seconds=-1)


def test_origin_canonicalization_is_fail_closed() -> None:
    assert canonical_origin("HTTPS://EXAMPLE.COM:443/") == "https://example.com"
    assert canonical_origin("http://localhost:3000/") == "http://localhost:3000"
    assert canonical_origin("https://example.com/path") == ""
    assert canonical_origin("https://example.com:invalid") == ""
    assert canonical_origin("not-an-origin") == ""


def test_origin_can_be_omitted_only_when_validation_is_disabled(
    settings,
    store: MemoryAuthStore,
) -> None:
    relaxed = settings.model_copy(update={"require_origin": False})
    service = AuthService(store=store, settings=relaxed)

    service.validate_origin(None)


@pytest.mark.asyncio
async def test_service_rejects_naive_clock(settings, store: MemoryAuthStore) -> None:
    service = AuthService(
        store=store,
        settings=settings,
        clock=lambda: datetime(2026, 8, 4, 12, 0),  # noqa: DTZ001
    )

    with pytest.raises(ValueError, match="timezone-aware"):
        await service.create_user(email="clock@example.com", display_name="Clock")
