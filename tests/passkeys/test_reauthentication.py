import pytest

from epok_auth.config import AuthSettings
from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.models import ReauthenticationMethod, SecurityEventType, SessionBundle
from epok_auth.passkeys.service import PasskeyService
from epok_auth.service import AuthService
from epok_auth.testing import MemoryAuthStore
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, MutableClock
from tests.passkeys.fakes import FakePasskeyAdapter

ORIGIN = "http://localhost:3000"


async def ready_services(
    store: MemoryAuthStore,
    settings: AuthSettings,
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
    registration = await passkeys.begin_registration(bundle.principal, ORIGIN)
    await passkeys.finish_registration(
        bundle.principal,
        registration.ceremony_id,
        "MacBook Touch ID",
        {"credential_id": b"key-1", "valid": True},
        ORIGIN,
    )
    return auth, passkeys, bundle


@pytest.mark.asyncio
async def test_passkey_reauthentication_survives_refresh_without_creating_session(
    store: MemoryAuthStore,
    settings: AuthSettings,
    clock: MutableClock,
) -> None:
    auth, passkeys, bundle = await ready_services(store, settings, clock)
    options = await passkeys.begin_reauthentication(bundle.principal, ORIGIN)
    challenge = store.passkey_challenges[options.ceremony_id]
    refreshed = await auth.refresh(
        bundle.refresh_token,
        bundle.csrf_token,
        bundle.csrf_token,
        origin=ORIGIN,
    )
    session_count = len(store.sessions)
    session_before = store.sessions[refreshed.principal.session_id]
    event_count = len(store.events)

    result = await passkeys.finish_reauthentication(
        refreshed.principal,
        options.ceremony_id,
        {"credential_id": b"key-1", "valid": True, "sign_count": 1},
        ORIGIN,
    )

    assert challenge.user_id == refreshed.principal.user_id
    assert challenge.family_id == refreshed.principal.family_id
    assert result.session_id == refreshed.principal.session_id
    assert result.family_id == refreshed.principal.family_id
    assert result.method is ReauthenticationMethod.PASSKEY
    assert len(store.sessions) == session_count
    assert store.sessions[refreshed.principal.session_id] == session_before
    passkey = next(iter(store.passkeys.values()))
    assert passkey.sign_count == 1
    assert passkey.last_used_at == clock.value
    new_events = store.events[event_count:]
    assert [event.event_type for event in new_events] == [
        SecurityEventType.REAUTHENTICATION_SUCCEEDED
    ]
    assert new_events[0].metadata["method"] == "passkey"
    assert "passkey_id" in new_events[0].metadata


@pytest.mark.asyncio
async def test_passkey_reauthentication_is_bound_to_family_and_single_use(
    store: MemoryAuthStore,
    settings: AuthSettings,
    clock: MutableClock,
) -> None:
    auth, passkeys, bundle = await ready_services(store, settings, clock)
    other = await auth.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    options = await passkeys.begin_reauthentication(bundle.principal, ORIGIN)

    with pytest.raises(AuthError) as wrong_family:
        await passkeys.finish_reauthentication(
            other.principal,
            options.ceremony_id,
            {"credential_id": b"key-1", "valid": True},
            ORIGIN,
        )

    result = await passkeys.finish_reauthentication(
        bundle.principal,
        options.ceremony_id,
        {"credential_id": b"key-1", "valid": True},
        ORIGIN,
    )
    with pytest.raises(AuthError) as replay:
        await passkeys.finish_reauthentication(
            bundle.principal,
            options.ceremony_id,
            {"credential_id": b"key-1", "valid": True},
            ORIGIN,
        )

    assert wrong_family.value.code is AuthErrorCode.PASSKEY_CHALLENGE_INVALID
    assert result.user_id == bundle.principal.user_id
    assert replay.value.code is AuthErrorCode.PASSKEY_CHALLENGE_INVALID


@pytest.mark.asyncio
async def test_invalid_passkey_reauthentication_consumes_challenge_and_records_failure(
    store: MemoryAuthStore,
    settings: AuthSettings,
    clock: MutableClock,
) -> None:
    _, passkeys, bundle = await ready_services(store, settings, clock)
    options = await passkeys.begin_reauthentication(bundle.principal, ORIGIN)
    passkey_before = next(iter(store.passkeys.values()))
    session_before = store.sessions[bundle.principal.session_id]

    with pytest.raises(AuthError) as invalid:
        await passkeys.finish_reauthentication(
            bundle.principal,
            options.ceremony_id,
            {"credential_id": b"key-1", "valid": False},
            ORIGIN,
        )
    with pytest.raises(AuthError) as replay:
        await passkeys.finish_reauthentication(
            bundle.principal,
            options.ceremony_id,
            {"credential_id": b"key-1", "valid": True},
            ORIGIN,
        )

    assert invalid.value.code is AuthErrorCode.PASSKEY_AUTHENTICATION_INVALID
    assert replay.value.code is AuthErrorCode.PASSKEY_CHALLENGE_INVALID
    assert next(iter(store.passkeys.values())) == passkey_before
    assert store.sessions[bundle.principal.session_id] == session_before
    failures = [
        event
        for event in store.events
        if event.event_type is SecurityEventType.REAUTHENTICATION_FAILED
    ]
    assert len(failures) == 2
    assert all(event.metadata == {"method": "passkey"} for event in failures)
