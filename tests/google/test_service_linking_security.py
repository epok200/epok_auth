from dataclasses import replace
from uuid import uuid4

import pytest

from epok_auth.config import GoogleAccountMode
from epok_auth.errors import AuthError, AuthErrorCode
from epok_auth.google.models import GoogleClaims
from epok_auth.models import RequestContext, SecurityEventType, UserStatus, UserUpdate
from epok_auth.store import StoreConflictError
from epok_auth.testing import MemoryAuthStore
from tests.conftest import MutableClock
from tests.google.fakes import ORIGIN, claims, create_harness


@pytest.mark.asyncio
@pytest.mark.parametrize("existing_user", [False, True])
async def test_recovery_distinguishes_missing_user_from_missing_google_identity(
    settings,
    clock: MutableClock,
    existing_user: bool,
) -> None:
    store = MemoryAuthStore()
    harness = create_harness(settings, store, clock)
    user_id = uuid4()
    if existing_user:
        user = await harness.auth.create_user(
            email="local@example.com",
            display_name="Local",
        )
        user_id = user.user.id

    with pytest.raises(AuthError) as captured:
        await harness.google.recover_password_access(user_id)

    expected = (
        AuthErrorCode.GOOGLE_IDENTITY_NOT_FOUND if existing_user else AuthErrorCode.USER_NOT_FOUND
    )
    assert captured.value.code is expected


@pytest.mark.asyncio
async def test_explicit_link_is_idempotent_but_rejects_a_second_google_identity(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    admin = await harness.auth.create_admin(
        email="admin@example.com",
        display_name="Admin",
        password="link conflict protects private colors",
    )
    await harness.auth.update_user(
        admin.id,
        UserUpdate(google_auto_link_allowed=True),
    )
    authorized_version = store.users[admin.id].security_version
    session = await harness.auth.login(admin.email, "link conflict protects private colors")

    first = await harness.google.begin_link(session.principal, ORIGIN)
    harness.verifier.add("first", claims(subject="first-subject"))
    linked = await harness.google.finish_link(
        session.principal,
        first.challenge_id,
        "first",
        ORIGIN,
    )
    linked_version = store.users[admin.id].security_version

    repeated = await harness.google.begin_link(session.principal, ORIGIN)
    harness.verifier.add("repeated", claims(subject="first-subject"))
    same = await harness.google.finish_link(
        session.principal,
        repeated.challenge_id,
        "repeated",
        ORIGIN,
    )

    conflicting = await harness.google.begin_link(session.principal, ORIGIN)
    harness.verifier.add("conflicting", claims(subject="second-subject"))
    with pytest.raises(AuthError) as captured:
        await harness.google.finish_link(
            session.principal,
            conflicting.challenge_id,
            "conflicting",
            ORIGIN,
        )

    assert same.id == linked.id
    assert linked_version == authorized_version + 1
    assert store.users[admin.id].security_version == linked_version
    assert store.users[admin.id].google_auto_link_allowed is False
    assert captured.value.code is AuthErrorCode.GOOGLE_IDENTITY_CONFLICT
    assert store.events[-1].event_type is SecurityEventType.GOOGLE_LINK_FAILED


@pytest.mark.asyncio
async def test_explicit_link_revalidates_account_after_challenge_creation(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    admin = await harness.auth.create_admin(
        email="admin@example.com",
        display_name="Admin",
        password="link status protects private colors",
    )
    second = await harness.auth.create_user(
        email="second@example.com",
        display_name="Second Admin",
        roles=("admin",),
    )
    session = await harness.auth.login(admin.email, "link status protects private colors")
    options = await harness.google.begin_link(session.principal, ORIGIN)
    await harness.auth.update_user(admin.id, UserUpdate(status=UserStatus.DISABLED))
    assert second.user.roles == ("admin",)
    harness.verifier.add("disabled-link", claims())

    with pytest.raises(AuthError) as captured:
        await harness.google.finish_link(
            session.principal,
            options.challenge_id,
            "disabled-link",
            ORIGIN,
        )

    assert captured.value.code is AuthErrorCode.INVALID_TOKEN


@pytest.mark.asyncio
async def test_link_requires_recent_session_without_pending_password_change(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    provisioned = await harness.auth.create_user(
        email="new@example.com",
        display_name="New",
    )
    temporary = await harness.auth.login(provisioned.user.email, provisioned.temporary_password)

    with pytest.raises(AuthError) as pending:
        await harness.google.begin_link(temporary.principal, ORIGIN)

    admin = await harness.auth.create_admin(
        email="admin@example.com",
        display_name="Admin",
        password="recent auth protects private colors",
    )
    recent = await harness.auth.login(admin.email, "recent auth protects private colors")
    clock.advance(seconds=harness.settings.google_link_max_age_seconds + 1)
    with pytest.raises(AuthError) as stale:
        await harness.google.begin_link(recent.principal, ORIGIN)

    assert pending.value.code is AuthErrorCode.FORBIDDEN
    assert stale.value.code is AuthErrorCode.FORBIDDEN


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "google_claims",
    [
        claims(issuer="https://issuer.example"),
        claims(subject=""),
        claims(email=None),
    ],
)
async def test_invalid_identity_claims_fail_before_account_resolution(
    settings,
    clock: MutableClock,
    google_claims: GoogleClaims,
) -> None:
    store = MemoryAuthStore()
    harness = create_harness(settings, store, clock, mode=GoogleAccountMode.OPEN)
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("invalid-claims", google_claims)

    with pytest.raises(AuthError) as captured:
        await harness.google.finish_login(options.challenge_id, "invalid-claims", ORIGIN)

    assert captured.value.code is AuthErrorCode.GOOGLE_CREDENTIAL_INVALID
    assert store.users == {}


@pytest.mark.asyncio
async def test_open_account_uses_email_prefix_when_google_name_is_invalid(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock, mode=GoogleAccountMode.OPEN)
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("fallback-name", claims(display_name="\n"))

    session = await harness.google.finish_login(options.challenge_id, "fallback-name", ORIGIN)

    assert session.principal.display_name == "person"


@pytest.mark.asyncio
async def test_login_retries_a_concurrent_identity_insert(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = create_harness(settings, store, clock, mode=GoogleAccountMode.OPEN)
    first = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("first", claims())
    created = await harness.google.finish_login(first.challenge_id, "first", ORIGIN)

    async def concurrent_insert(*args, **kwargs):
        del args, kwargs
        raise StoreConflictError("simulated concurrent insert")

    monkeypatch.setattr(harness.google, "_login", concurrent_insert)
    second = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("second", claims())
    retried = await harness.google.finish_login(second.challenge_id, "second", ORIGIN)

    assert retried.principal.user_id == created.principal.user_id

    await harness.auth.update_user(
        created.principal.user_id,
        UserUpdate(status=UserStatus.DISABLED),
    )
    with pytest.raises(AuthError) as disabled:
        await harness.google._login_linked_after_conflict(
            claims(),
            clock(),
            RequestContext(),
        )
    with pytest.raises(AuthError) as missing:
        await harness.google._login_linked_after_conflict(
            claims(subject="missing-subject"),
            clock(),
            RequestContext(),
        )

    assert disabled.value.code is AuthErrorCode.GOOGLE_CREDENTIAL_INVALID
    assert missing.value.code is AuthErrorCode.GOOGLE_CREDENTIAL_INVALID


@pytest.mark.asyncio
async def test_link_retries_only_the_identity_inserted_for_the_same_user(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = create_harness(settings, store, clock)
    admin = await harness.auth.create_admin(
        email="admin@example.com",
        display_name="Admin",
        password="concurrency checks protect private colors",
    )
    session = await harness.auth.login(
        admin.email,
        "concurrency checks protect private colors",
    )
    first = await harness.google.begin_link(session.principal, ORIGIN)
    harness.verifier.add("first", claims())
    identity = await harness.google.finish_link(
        session.principal,
        first.challenge_id,
        "first",
        ORIGIN,
    )

    async def concurrent_insert(*args, **kwargs):
        del args, kwargs
        raise StoreConflictError("simulated concurrent insert")

    monkeypatch.setattr(harness.google, "_link", concurrent_insert)
    second = await harness.google.begin_link(session.principal, ORIGIN)
    harness.verifier.add("second", claims())
    retried = await harness.google.finish_link(
        session.principal,
        second.challenge_id,
        "second",
        ORIGIN,
    )

    assert retried.id == identity.id

    with pytest.raises(AuthError) as captured:
        await harness.google._linked_after_conflict(
            session.principal,
            claims(subject="missing-subject"),
            clock(),
            RequestContext(),
        )

    assert captured.value.code is AuthErrorCode.GOOGLE_IDENTITY_CONFLICT
    assert store.events[-1].event_type is SecurityEventType.GOOGLE_LINK_FAILED


@pytest.mark.asyncio
async def test_link_conflict_retry_revalidates_session(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = create_harness(settings, store, clock)
    admin = await harness.auth.create_admin(
        email="admin@example.com",
        display_name="Admin",
        password="conflict retry protects private colors",
    )
    session = await harness.auth.login(admin.email, "conflict retry protects private colors")
    options = await harness.google.begin_link(session.principal, ORIGIN)
    harness.verifier.add("conflict", claims())

    async def invalidate_session_and_conflict(principal, *args, **kwargs):
        del args, kwargs
        stored = store.sessions[principal.session_id]
        store.sessions[principal.session_id] = replace(stored, revoked_at=clock())
        raise StoreConflictError("simulated concurrent insert")

    monkeypatch.setattr(harness.google, "_link", invalidate_session_and_conflict)

    with pytest.raises(AuthError) as captured:
        await harness.google.finish_link(
            session.principal,
            options.challenge_id,
            "conflict",
            ORIGIN,
        )

    assert captured.value.code is AuthErrorCode.INVALID_TOKEN
    assert store.events[-1].event_type is SecurityEventType.GOOGLE_LINK_FAILED
