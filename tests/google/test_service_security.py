import asyncio

import pytest

from epok_auth.config import GoogleAccountMode
from epok_auth.errors import AuthError, AuthErrorCode
from epok_auth.google.adapter import (
    GoogleServiceUnavailableError,
    GoogleVerificationError,
)
from epok_auth.models import SecurityEventType, UserStatus, UserUpdate
from epok_auth.testing import MemoryAuthStore
from tests.conftest import MutableClock
from tests.google.fakes import ORIGIN, claims, create_harness


@pytest.mark.asyncio
@pytest.mark.security
async def test_challenge_is_single_use_even_after_origin_mismatch(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    configured = settings.model_copy(update={"trusted_origins": (ORIGIN, "http://127.0.0.1:3000")})
    harness = create_harness(configured, store, clock, mode=GoogleAccountMode.OPEN)
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("token", claims())

    with pytest.raises(AuthError) as wrong_origin:
        await harness.google.finish_login(
            options.challenge_id,
            "token",
            "http://127.0.0.1:3000",
        )
    with pytest.raises(AuthError) as replay:
        await harness.google.finish_login(options.challenge_id, "token", ORIGIN)

    assert wrong_origin.value.code is AuthErrorCode.GOOGLE_CHALLENGE_INVALID
    assert replay.value.code is AuthErrorCode.GOOGLE_CHALLENGE_INVALID
    assert harness.verifier.calls == []


@pytest.mark.asyncio
@pytest.mark.security
async def test_expired_challenge_is_rejected_before_token_verification(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock, mode=GoogleAccountMode.OPEN)
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("token", claims())
    clock.advance(seconds=harness.settings.google_challenge_ttl_seconds)

    with pytest.raises(AuthError) as captured:
        await harness.google.finish_login(options.challenge_id, "token", ORIGIN)

    assert captured.value.code is AuthErrorCode.GOOGLE_CHALLENGE_INVALID
    assert harness.verifier.calls == []


@pytest.mark.asyncio
async def test_starting_challenge_removes_expired_challenges(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    expired = await harness.google.begin_login(ORIGIN)
    clock.advance(seconds=harness.settings.google_challenge_ttl_seconds)

    current = await harness.google.begin_login(ORIGIN)

    assert expired.challenge_id not in store.google_challenges
    assert current.challenge_id in store.google_challenges


@pytest.mark.asyncio
async def test_google_challenge_requires_origin(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)

    with pytest.raises(AuthError) as captured:
        await harness.google.begin_login(None)

    assert captured.value.code is AuthErrorCode.INVALID_ORIGIN


@pytest.mark.asyncio
async def test_google_challenge_rejects_naive_clock(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    clock.value = clock.value.replace(tzinfo=None)

    with pytest.raises(ValueError, match="timezone-aware"):
        await harness.google.begin_login(ORIGIN)


@pytest.mark.asyncio
async def test_google_verification_rejects_naive_clock(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("token", claims())
    clock.value = clock.value.replace(tzinfo=None)

    with pytest.raises(ValueError, match="timezone-aware"):
        await harness.google.finish_login(options.challenge_id, "token", ORIGIN)


@pytest.mark.asyncio
async def test_link_challenge_requires_current_user(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    admin = await harness.auth.create_admin(
        email="admin@example.com",
        display_name="Admin",
        password="current user protects private colors",
    )
    session = await harness.auth.login(admin.email, "current user protects private colors")
    del store.users[admin.id]

    with pytest.raises(AuthError) as captured:
        await harness.google.begin_link(session.principal, ORIGIN)

    assert captured.value.code is AuthErrorCode.INVALID_TOKEN


@pytest.mark.asyncio
@pytest.mark.security
async def test_malformed_and_oversized_credentials_are_generic_and_consumed(
    settings,
    clock: MutableClock,
) -> None:
    store = MemoryAuthStore()
    harness = create_harness(
        settings,
        store,
        clock,
        mode=GoogleAccountMode.OPEN,
        max_credential_chars=32,
    )
    oversized = "private-google-token" * 10
    first = await harness.google.begin_login(ORIGIN)

    with pytest.raises(AuthError) as too_large:
        await harness.google.finish_login(first.challenge_id, oversized, ORIGIN)

    second = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("malformed", GoogleVerificationError("raw token was invalid"))
    with pytest.raises(AuthError) as malformed:
        await harness.google.finish_login(second.challenge_id, "malformed", ORIGIN)

    for error in (too_large.value, malformed.value):
        assert error.code is AuthErrorCode.GOOGLE_CREDENTIAL_INVALID
        assert "private-google-token" not in error.detail
        assert "raw token" not in error.detail
    assert all("credential" not in event.metadata for event in store.events)


@pytest.mark.asyncio
async def test_google_outage_maps_to_retryable_service_error(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("outage", GoogleServiceUnavailableError("network detail"))

    with pytest.raises(AuthError) as captured:
        await harness.google.finish_login(options.challenge_id, "outage", ORIGIN)

    assert captured.value.code is AuthErrorCode.GOOGLE_SERVICE_UNAVAILABLE
    assert captured.value.status_code == 503
    assert store.events[-1].metadata == {"provider_unavailable": True}


@pytest.mark.asyncio
@pytest.mark.security
async def test_hosted_domain_allowlist_applies_to_link_and_every_later_login(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(
        settings,
        store,
        clock,
        hosted_domains=("company.example",),
    )
    admin = await harness.auth.create_admin(
        email="admin@example.com",
        display_name="Admin",
        password="domain policy protects private colors",
    )
    local_session = await harness.auth.login(admin.email, "domain policy protects private colors")
    link = await harness.google.begin_link(local_session.principal, ORIGIN)
    harness.verifier.add(
        "allowed",
        claims(email="admin@company.example", hosted_domain="company.example"),
    )
    await harness.google.finish_link(
        local_session.principal,
        link.challenge_id,
        "allowed",
        ORIGIN,
    )

    login = await harness.google.begin_login(ORIGIN)
    harness.verifier.add(
        "wrong-domain",
        claims(email="admin@other.example", hosted_domain="other.example"),
    )
    with pytest.raises(AuthError) as captured:
        await harness.google.finish_login(login.challenge_id, "wrong-domain", ORIGIN)

    assert captured.value.code is AuthErrorCode.GOOGLE_CREDENTIAL_INVALID


@pytest.mark.asyncio
@pytest.mark.security
async def test_invalid_hosted_domain_claim_cannot_authorize_open_account(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock, mode=GoogleAccountMode.OPEN)
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add(
        "invalid-domain",
        claims(email="person@example.com", hosted_domain="../example.com"),
    )

    with pytest.raises(AuthError):
        await harness.google.finish_login(options.challenge_id, "invalid-domain", ORIGIN)

    assert store.users == {}


@pytest.mark.asyncio
async def test_concurrent_open_logins_create_one_account_and_two_valid_sessions(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock, mode=GoogleAccountMode.OPEN)
    first, second = await asyncio.gather(
        harness.google.begin_login(ORIGIN),
        harness.google.begin_login(ORIGIN),
    )
    harness.verifier.add("first", claims())
    harness.verifier.add("second", claims())

    sessions = await asyncio.gather(
        harness.google.finish_login(first.challenge_id, "first", ORIGIN),
        harness.google.finish_login(second.challenge_id, "second", ORIGIN),
    )

    assert len(store.users) == 1
    assert len(store.external_identities) == 1
    assert sessions[0].principal.user_id == sessions[1].principal.user_id
    assert sessions[0].principal.session_id != sessions[1].principal.session_id


@pytest.mark.asyncio
async def test_recovery_removes_google_link_revokes_sessions_and_restores_password(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock, mode=GoogleAccountMode.OPEN)
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("create", claims())
    google_session = await harness.google.finish_login(options.challenge_id, "create", ORIGIN)

    recovered = await harness.google.recover_password_access(google_session.principal.user_id)

    assert recovered.user.security_version == 1
    assert recovered.user.password_login_enabled is True
    assert recovered.user.must_change_password is True
    assert recovered.user.google_auto_link_allowed is False
    assert store.external_identities == {}
    with pytest.raises(AuthError):
        await harness.auth.authenticate(google_session.access_token)
    password_session = await harness.auth.login(recovered.user.email, recovered.temporary_password)
    assert password_session.principal.user_id == recovered.user.id
    assert any(
        event.event_type is SecurityEventType.GOOGLE_RECOVERY_COMPLETED for event in store.events
    )


@pytest.mark.asyncio
async def test_recovery_and_password_reset_clear_preauthorization(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    provisioned = await harness.auth.create_user(
        email="employee@example.com",
        display_name="Employee",
        google_auto_link_allowed=True,
    )

    reset = await harness.auth.reset_password(provisioned.user.id)

    assert reset.user.google_auto_link_allowed is False
    assert reset.user.password_login_enabled is True


@pytest.mark.asyncio
async def test_disabled_linked_user_cannot_login_with_google(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    admin = await harness.auth.create_admin(
        email="admin@example.com",
        display_name="Admin",
        password="disable test protects private colors",
    )
    second = await harness.auth.create_user(
        email="second@example.com",
        display_name="Second Admin",
        roles=("admin",),
    )
    session = await harness.auth.login(admin.email, "disable test protects private colors")
    link = await harness.google.begin_link(session.principal, ORIGIN)
    harness.verifier.add("link", claims())
    await harness.google.finish_link(session.principal, link.challenge_id, "link", ORIGIN)
    await harness.auth.update_user(admin.id, UserUpdate(status=UserStatus.DISABLED))
    assert second.user.roles == ("admin",)

    login = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("disabled", claims())
    with pytest.raises(AuthError):
        await harness.google.finish_login(login.challenge_id, "disabled", ORIGIN)


@pytest.mark.asyncio
@pytest.mark.security
async def test_password_attempts_cannot_lock_a_google_only_account(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock, mode=GoogleAccountMode.OPEN)
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("create", claims())
    google_session = await harness.google.finish_login(options.challenge_id, "create", ORIGIN)
    user_id = google_session.principal.user_id

    for _ in range(harness.settings.login_max_attempts + 1):
        with pytest.raises(AuthError):
            await harness.auth.login("person@gmail.com", "attacker password never works")

    user = store.users[user_id]
    assert user.failed_login_attempts == 0
    assert user.locked_until is None
    next_options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("next-login", claims())
    next_session = await harness.google.finish_login(
        next_options.challenge_id,
        "next-login",
        ORIGIN,
    )
    assert next_session.principal.user_id == user_id
