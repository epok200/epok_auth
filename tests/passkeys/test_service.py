import asyncio
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.models import Principal, SecurityEventType, SessionBundle, UserStatus
from epok_auth.passkeys.service import PasskeyService
from epok_auth.service import AuthService
from epok_auth.testing import MemoryAuthStore
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, MutableClock
from tests.passkeys.fakes import FakePasskeyAdapter

ORIGIN = "http://localhost:3000"


async def ready_services(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> tuple[AuthService, PasskeyService, SessionBundle]:
    passkey_settings = settings.model_copy(update={"passkey_rp_id": "localhost"})
    auth = AuthService(store=store, settings=passkey_settings, clock=clock)
    await auth.create_admin(
        email=ADMIN_EMAIL,
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    bundle = await auth.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    passkeys = PasskeyService(
        store=store,
        settings=passkey_settings,
        signer=auth.signer,
        adapter=FakePasskeyAdapter(),
        clock=clock,
    )
    return auth, passkeys, bundle


async def register_passkey(
    passkeys: PasskeyService,
    principal: Principal,
    credential_id: bytes = b"key-1",
):
    options = await passkeys.begin_registration(principal, ORIGIN)
    credential = await passkeys.finish_registration(
        principal,
        options.ceremony_id,
        "MacBook Touch ID",
        {"credential_id": credential_id, "valid": True},
        ORIGIN,
    )
    return options, credential


@pytest.mark.asyncio
async def test_registration_lists_and_revokes_passkey(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    _, passkeys, bundle = await ready_services(store, settings, clock)
    initial_version = store.users[bundle.principal.user_id].security_version

    options, credential = await register_passkey(passkeys, bundle.principal)
    registered_version = store.users[bundle.principal.user_id].security_version
    listed = await passkeys.list_passkeys(bundle.principal)
    await passkeys.revoke_passkey(bundle.principal, credential.id, ORIGIN)

    assert options.public_key["challenge"]
    assert listed == (credential,)
    assert registered_version == initial_version + 1
    assert store.users[bundle.principal.user_id].security_version == registered_version + 1
    assert await passkeys.list_passkeys(bundle.principal) == ()
    assert store.passkeys[credential.id].revoked_at == clock.value
    assert SecurityEventType.PASSKEY_REGISTERED in {event.event_type for event in store.events}
    assert SecurityEventType.PASSKEY_REVOKED in {event.event_type for event in store.events}


@pytest.mark.asyncio
async def test_registration_challenge_is_single_use_after_invalid_response(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    _, passkeys, bundle = await ready_services(store, settings, clock)
    options = await passkeys.begin_registration(bundle.principal, ORIGIN)

    with pytest.raises(AuthError) as invalid:
        await passkeys.finish_registration(
            bundle.principal,
            options.ceremony_id,
            "Laptop",
            {"credential_id": b"key-1", "valid": False},
            ORIGIN,
        )
    with pytest.raises(AuthError) as replay:
        await passkeys.finish_registration(
            bundle.principal,
            options.ceremony_id,
            "Laptop",
            {"credential_id": b"key-1", "valid": True},
            ORIGIN,
        )

    assert invalid.value.code is AuthErrorCode.PASSKEY_REGISTRATION_INVALID
    assert replay.value.code is AuthErrorCode.PASSKEY_CHALLENGE_INVALID
    assert len(store.passkeys) == 0


@pytest.mark.asyncio
async def test_expired_or_cross_origin_challenge_fails_closed(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    short_lived = settings.model_copy(update={"passkey_challenge_ttl_seconds": 60})
    _, passkeys, bundle = await ready_services(store, short_lived, clock)
    expired = await passkeys.begin_registration(bundle.principal, ORIGIN)
    clock.advance(seconds=61)

    with pytest.raises(AuthError) as expiry:
        await passkeys.finish_registration(
            bundle.principal,
            expired.ceremony_id,
            "Laptop",
            {"credential_id": b"key-1", "valid": True},
            ORIGIN,
        )

    fresh = await passkeys.begin_registration(bundle.principal, ORIGIN)
    with pytest.raises(AuthError) as origin:
        await passkeys.finish_registration(
            bundle.principal,
            fresh.ceremony_id,
            "Laptop",
            {"credential_id": b"key-1", "valid": True},
            "https://evil.example",
        )

    assert expiry.value.code is AuthErrorCode.PASSKEY_CHALLENGE_INVALID
    assert origin.value.code is AuthErrorCode.INVALID_ORIGIN


@pytest.mark.asyncio
async def test_registration_limit_is_transactional_under_concurrency(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    limited = settings.model_copy(
        update={"passkey_rp_id": "localhost", "passkey_max_credentials_per_user": 1}
    )
    auth = AuthService(store=store, settings=limited, clock=clock)
    await auth.create_admin(email=ADMIN_EMAIL, display_name="Admin", password=ADMIN_PASSWORD)
    bundle = await auth.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    passkeys = PasskeyService(
        store=store,
        settings=limited,
        signer=auth.signer,
        adapter=FakePasskeyAdapter(),
        clock=clock,
    )
    first = await passkeys.begin_registration(bundle.principal, ORIGIN)
    second = await passkeys.begin_registration(bundle.principal, ORIGIN)

    async def finish(ceremony_id, credential_id: bytes) -> object:
        try:
            return await passkeys.finish_registration(
                bundle.principal,
                ceremony_id,
                "Laptop",
                {"credential_id": credential_id, "valid": True},
                ORIGIN,
            )
        except AuthError as error:
            return error

    results = await asyncio.gather(
        finish(first.ceremony_id, b"key-1"),
        finish(second.ceremony_id, b"key-2"),
    )

    assert sum(not isinstance(result, AuthError) for result in results) == 1
    failures = [result for result in results if isinstance(result, AuthError)]
    assert failures[0].code is AuthErrorCode.PASSKEY_LIMIT_REACHED
    assert len(await passkeys.list_passkeys(bundle.principal)) == 1


@pytest.mark.asyncio
async def test_passkey_authentication_issues_authoritative_session(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    auth, passkeys, bundle = await ready_services(store, settings, clock)
    _, credential = await register_passkey(passkeys, bundle.principal)
    options = await passkeys.begin_authentication(ORIGIN)

    session = await passkeys.finish_authentication(
        options.ceremony_id,
        {"credential_id": credential.credential_id, "valid": True, "sign_count": 1},
        ORIGIN,
    )

    assert (await auth.authenticate(session.access_token)).user_id == bundle.principal.user_id
    assert store.passkeys[credential.id].sign_count == 1
    assert store.passkeys[credential.id].last_used_at == clock.value
    assert session.principal.authenticated_at == clock.value
    assert SecurityEventType.PASSKEY_LOGIN_SUCCEEDED in {event.event_type for event in store.events}


@pytest.mark.asyncio
@pytest.mark.security
async def test_passkey_authentication_rejects_a_pending_account(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    _, passkeys, bundle = await ready_services(store, settings, clock)
    _, credential = await register_passkey(passkeys, bundle.principal)
    user = store.users[bundle.principal.user_id]
    async with store.transaction() as transaction:
        await transaction.update_user(replace(user, status=UserStatus.PENDING_ACTIVATION))
    existing_sessions = len(store.sessions)
    options = await passkeys.begin_authentication(ORIGIN)

    with pytest.raises(AuthError) as captured:
        await passkeys.finish_authentication(
            options.ceremony_id,
            {"credential_id": credential.credential_id, "valid": True, "sign_count": 1},
            ORIGIN,
        )

    assert captured.value.code is AuthErrorCode.PASSKEY_AUTHENTICATION_INVALID
    assert len(store.sessions) == existing_sessions
    assert SecurityEventType.PASSKEY_LOGIN_FAILED in {event.event_type for event in store.events}


@pytest.mark.asyncio
async def test_authentication_rejects_replay_unknown_and_revoked_credentials(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    _, passkeys, bundle = await ready_services(store, settings, clock)
    _, credential = await register_passkey(passkeys, bundle.principal)
    first = await passkeys.begin_authentication(ORIGIN)
    await passkeys.finish_authentication(
        first.ceremony_id,
        {"credential_id": credential.credential_id, "valid": True},
        ORIGIN,
    )

    with pytest.raises(AuthError) as replay:
        await passkeys.finish_authentication(
            first.ceremony_id,
            {"credential_id": credential.credential_id, "valid": True},
            ORIGIN,
        )

    unknown = await passkeys.begin_authentication(ORIGIN)
    with pytest.raises(AuthError) as missing:
        await passkeys.finish_authentication(
            unknown.ceremony_id,
            {"credential_id": b"unknown", "valid": True},
            ORIGIN,
        )

    await passkeys.revoke_passkey(bundle.principal, credential.id, ORIGIN)
    revoked = await passkeys.begin_authentication(ORIGIN)
    with pytest.raises(AuthError) as disabled:
        await passkeys.finish_authentication(
            revoked.ceremony_id,
            {"credential_id": credential.credential_id, "valid": True},
            ORIGIN,
        )

    assert replay.value.code is AuthErrorCode.PASSKEY_CHALLENGE_INVALID
    assert missing.value.code is AuthErrorCode.PASSKEY_AUTHENTICATION_INVALID
    assert disabled.value.code is AuthErrorCode.PASSKEY_AUTHENTICATION_INVALID
    assert missing.value.detail == disabled.value.detail


@pytest.mark.asyncio
async def test_passkey_management_requires_recent_authentication(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    _, passkeys, bundle = await ready_services(store, settings, clock)
    stale = replace(bundle.principal, authenticated_at=clock.value.replace(year=2025))
    pending = replace(bundle.principal, must_change_password=True)

    with pytest.raises(AuthError) as captured:
        await passkeys.begin_registration(stale, ORIGIN)
    with pytest.raises(AuthError) as password_change:
        await passkeys.begin_registration(pending, ORIGIN)

    assert captured.value.code is AuthErrorCode.FORBIDDEN
    assert password_change.value.code is AuthErrorCode.PASSWORD_CHANGE_REQUIRED


@pytest.mark.asyncio
async def test_passkey_origin_must_be_trusted_and_match_rp_id(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    _, passkeys, bundle = await ready_services(store, settings, clock)

    with pytest.raises(AuthError) as untrusted:
        await passkeys.begin_registration(bundle.principal, "https://evil.example")

    incompatible_settings = settings.model_copy(
        update={
            "passkey_rp_id": "example.com",
            "trusted_origins": (ORIGIN,),
        }
    )
    incompatible = PasskeyService(
        store=store,
        settings=incompatible_settings,
        signer=passkeys.signer,
        adapter=FakePasskeyAdapter(),
        clock=clock,
    )
    with pytest.raises(AuthError) as wrong_rp:
        await incompatible.begin_registration(bundle.principal, ORIGIN)

    assert untrusted.value.code is AuthErrorCode.INVALID_ORIGIN
    assert wrong_rp.value.code is AuthErrorCode.INVALID_ORIGIN


@pytest.mark.asyncio
async def test_registration_origin_is_bound_to_the_created_challenge(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    configured = settings.model_copy(
        update={
            "passkey_rp_id": "localhost",
            "trusted_origins": (ORIGIN, "http://localhost:4000"),
        }
    )
    auth = AuthService(store=store, settings=configured, clock=clock)
    await auth.create_admin(email=ADMIN_EMAIL, display_name="Admin", password=ADMIN_PASSWORD)
    bundle = await auth.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    passkeys = PasskeyService(
        store=store,
        settings=configured,
        signer=auth.signer,
        adapter=FakePasskeyAdapter(),
        clock=clock,
    )
    options = await passkeys.begin_registration(bundle.principal, ORIGIN)

    with pytest.raises(AuthError) as swapped:
        await passkeys.finish_registration(
            bundle.principal,
            options.ceremony_id,
            "Laptop",
            {"credential_id": b"key-1", "valid": True},
            "http://localhost:4000",
        )
    with pytest.raises(AuthError) as replay:
        await passkeys.finish_registration(
            bundle.principal,
            options.ceremony_id,
            "Laptop",
            {"credential_id": b"key-1", "valid": True},
            ORIGIN,
        )

    assert swapped.value.code is AuthErrorCode.PASSKEY_CHALLENGE_INVALID
    assert replay.value.code is AuthErrorCode.PASSKEY_CHALLENGE_INVALID


@pytest.mark.asyncio
async def test_registration_rejects_duplicate_oversized_and_limit_at_start(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    auth, passkeys, bundle = await ready_services(store, settings, clock)
    _, credential = await register_passkey(passkeys, bundle.principal)

    duplicate = await passkeys.begin_registration(bundle.principal, ORIGIN)
    with pytest.raises(AuthError) as duplicate_error:
        await passkeys.finish_registration(
            bundle.principal,
            duplicate.ceremony_id,
            "Duplicate",
            {"credential_id": credential.credential_id, "valid": True},
            ORIGIN,
        )

    oversized = await passkeys.begin_registration(bundle.principal, ORIGIN)
    with pytest.raises(AuthError) as oversized_error:
        await passkeys.finish_registration(
            bundle.principal,
            oversized.ceremony_id,
            "Oversized",
            {"credential_id": b"x" * 1024, "valid": True},
            ORIGIN,
        )

    limited_settings = passkeys.settings.model_copy(update={"passkey_max_credentials_per_user": 1})
    limited = PasskeyService(
        store=store,
        settings=limited_settings,
        signer=auth.signer,
        adapter=FakePasskeyAdapter(),
        clock=clock,
    )
    with pytest.raises(AuthError) as limit_error:
        await limited.begin_registration(bundle.principal, ORIGIN)

    assert duplicate_error.value.code is AuthErrorCode.PASSKEY_EXISTS
    assert oversized_error.value.code is AuthErrorCode.PASSKEY_REGISTRATION_INVALID
    assert limit_error.value.code is AuthErrorCode.PASSKEY_LIMIT_REACHED


@pytest.mark.asyncio
async def test_authentication_rejects_malformed_invalid_and_changed_device(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    _, passkeys, bundle = await ready_services(store, settings, clock)
    _, credential = await register_passkey(passkeys, bundle.principal)

    for payload in (
        {"valid": True},
        {"credential_id": credential.credential_id, "valid": False},
        {
            "credential_id": credential.credential_id,
            "valid": True,
            "device_type": "single_device",
        },
    ):
        options = await passkeys.begin_authentication(ORIGIN)
        with pytest.raises(AuthError) as captured:
            await passkeys.finish_authentication(
                options.ceremony_id,
                payload,
                ORIGIN,
            )
        assert captured.value.code is AuthErrorCode.PASSKEY_AUTHENTICATION_INVALID


@pytest.mark.asyncio
async def test_management_rejects_invalid_name_missing_origin_and_double_revoke(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    _, passkeys, bundle = await ready_services(store, settings, clock)
    options = await passkeys.begin_registration(bundle.principal, ORIGIN)
    with pytest.raises(AuthError) as name_error:
        await passkeys.finish_registration(
            bundle.principal,
            options.ceremony_id,
            "   ",
            {"credential_id": b"key-1", "valid": True},
            ORIGIN,
        )
    credential = await passkeys.finish_registration(
        bundle.principal,
        options.ceremony_id,
        "Laptop",
        {"credential_id": b"key-1", "valid": True},
        ORIGIN,
    )
    with pytest.raises(AuthError) as missing_origin:
        await passkeys.revoke_passkey(bundle.principal, credential.id, None)
    await passkeys.revoke_passkey(bundle.principal, credential.id, ORIGIN)
    with pytest.raises(AuthError) as missing:
        await passkeys.revoke_passkey(bundle.principal, credential.id, ORIGIN)

    assert name_error.value.code is AuthErrorCode.PASSKEY_NAME_INVALID
    assert missing_origin.value.code is AuthErrorCode.INVALID_ORIGIN
    assert missing.value.code is AuthErrorCode.PASSKEY_NOT_FOUND


def test_passkey_service_requires_rp_configuration_and_aware_clock(
    store: MemoryAuthStore,
    settings,
) -> None:
    auth = AuthService(store=store, settings=settings)
    with pytest.raises(ValueError, match="passkey_rp_id"):
        PasskeyService(
            store=store,
            settings=settings,
            signer=auth.signer,
            adapter=FakePasskeyAdapter(),
        )

    configured = settings.model_copy(update={"passkey_rp_id": "localhost"})
    passkeys = PasskeyService(
        store=store,
        settings=configured,
        signer=auth.signer,
        adapter=FakePasskeyAdapter(),
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC).replace(tzinfo=None),
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        asyncio.run(passkeys.begin_authentication(ORIGIN))
