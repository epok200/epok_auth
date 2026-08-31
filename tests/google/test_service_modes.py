from dataclasses import replace

import pytest

from epok_auth.config import GoogleAccountMode
from epok_auth.errors import AuthError, AuthErrorCode
from epok_auth.google.models import GOOGLE_ISSUER
from epok_auth.models import SecurityEventType, UserStatus, UserUpdate
from epok_auth.testing import MemoryAuthStore
from tests.conftest import MutableClock
from tests.google.fakes import ORIGIN, claims, create_harness


@pytest.mark.asyncio
async def test_linked_only_rejects_unknown_identity_without_creating_account(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("unknown", claims())

    with pytest.raises(AuthError) as captured:
        await harness.google.finish_login(options.challenge_id, "unknown", ORIGIN)

    assert captured.value.code is AuthErrorCode.GOOGLE_CREDENTIAL_INVALID
    assert store.users == {}
    assert store.external_identities == {}
    assert store.events[-1].event_type is SecurityEventType.GOOGLE_LOGIN_FAILED


@pytest.mark.asyncio
async def test_explicit_link_accepts_a_different_google_email_and_preserves_local_account(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    local = await harness.auth.create_admin(
        email="owner@example.com",
        display_name="Local Owner",
        password="local password protects private colors",
    )
    password_session = await harness.auth.login(
        local.email,
        "local password protects private colors",
    )
    options = await harness.google.begin_link(password_session.principal, ORIGIN)
    harness.verifier.add(
        "link-token",
        claims(email="different@gmail.com", display_name="Different Name"),
    )

    identity = await harness.google.finish_link(
        password_session.principal,
        options.challenge_id,
        "link-token",
        ORIGIN,
    )
    login_options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add(
        "login-token",
        claims(email="changed@gmail.com", display_name="Changed Name"),
    )
    google_session = await harness.google.finish_login(
        login_options.challenge_id,
        "login-token",
        ORIGIN,
    )

    stored = store.users[local.id]
    assert identity.user_id == local.id
    assert identity.email == "different@gmail.com"
    assert google_session.principal.user_id == local.id
    assert stored.email == "owner@example.com"
    assert stored.display_name == "Local Owner"
    assert stored.password_login_enabled is True
    password_login = await harness.auth.login(
        local.email,
        "local password protects private colors",
    )
    assert password_login.principal.user_id == local.id


@pytest.mark.asyncio
async def test_preauthorized_login_links_exact_authoritative_email_and_disables_password(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(
        settings,
        store,
        clock,
        mode=GoogleAccountMode.PREAUTHORIZED,
    )
    provisioned = await harness.auth.create_user(
        email="employee@example.com",
        display_name="Employee",
        google_auto_link_allowed=True,
    )
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add(
        "employee-token",
        claims(email="EMPLOYEE@example.com", hosted_domain="example.com"),
    )

    session = await harness.google.finish_login(
        options.challenge_id,
        "employee-token",
        ORIGIN,
    )

    user = store.users[provisioned.user.id]
    assert session.principal.user_id == user.id
    assert user.password_login_enabled is False
    assert user.google_auto_link_allowed is False
    assert user.must_change_password is False
    assert len(store.external_identities) == 1
    with pytest.raises(AuthError):
        await harness.auth.login(user.email, provisioned.temporary_password)


@pytest.mark.asyncio
@pytest.mark.security
async def test_preauthorized_login_never_replaces_a_stable_password(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(
        settings,
        store,
        clock,
        mode=GoogleAccountMode.PREAUTHORIZED,
    )
    admin = await harness.auth.create_admin(
        email="employee@example.com",
        display_name="Employee",
        password="stable password protects private colors",
    )
    await harness.auth.update_user(
        admin.id,
        UserUpdate(google_auto_link_allowed=True),
    )
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add(
        "employee-token",
        claims(email=admin.email, hosted_domain="example.com"),
    )

    with pytest.raises(AuthError) as captured:
        await harness.google.finish_login(options.challenge_id, "employee-token", ORIGIN)

    assert captured.value.code is AuthErrorCode.GOOGLE_CREDENTIAL_INVALID
    assert store.external_identities == {}
    password_session = await harness.auth.login(
        admin.email,
        "stable password protects private colors",
    )
    assert password_session.principal.user_id == admin.id


@pytest.mark.asyncio
@pytest.mark.security
async def test_preauthorized_google_login_rejects_a_pending_account(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(
        settings,
        store,
        clock,
        mode=GoogleAccountMode.PREAUTHORIZED,
    )
    provisioned = await harness.auth.create_user(
        email="pending@example.com",
        display_name="Pending",
        google_auto_link_allowed=True,
    )
    async with store.transaction() as transaction:
        await transaction.update_user(
            replace(provisioned.user, status=UserStatus.PENDING_ACTIVATION)
        )
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add(
        "pending-token",
        claims(email=provisioned.user.email, hosted_domain="example.com"),
    )

    with pytest.raises(AuthError) as captured:
        await harness.google.finish_login(options.challenge_id, "pending-token", ORIGIN)

    assert captured.value.code is AuthErrorCode.GOOGLE_CREDENTIAL_INVALID
    assert store.external_identities == {}
    assert store.sessions == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        ("other@example.com", True, "example.com", True),
        ("employee@example.com", False, "example.com", True),
        ("employee@example.com", True, None, True),
        ("employee@example.com", True, "example.com", False),
    ],
)
async def test_preauthorized_login_fails_closed_when_any_condition_is_missing(
    settings,
    clock: MutableClock,
    case: tuple[str, bool, str | None, bool],
) -> None:
    email, verified, hosted_domain, allowed = case
    store = MemoryAuthStore()
    harness = create_harness(
        settings,
        store,
        clock,
        mode=GoogleAccountMode.PREAUTHORIZED,
    )
    user = await harness.auth.create_user(
        email="employee@example.com",
        display_name="Employee",
        google_auto_link_allowed=allowed,
    )
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add(
        "denied",
        claims(email=email, verified=verified, hosted_domain=hosted_domain),
    )

    with pytest.raises(AuthError) as captured:
        await harness.google.finish_login(options.challenge_id, "denied", ORIGIN)

    assert captured.value.code is AuthErrorCode.GOOGLE_CREDENTIAL_INVALID
    assert store.users[user.user.id].password_login_enabled is True
    assert store.external_identities == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        ("new@gmail.com", True, None, True),
        ("new@workspace.example", True, "workspace.example", True),
        ("new@third-party.example", True, None, False),
        ("new@gmail.com", False, None, False),
    ],
)
async def test_open_mode_creates_only_authoritative_google_accounts(
    settings,
    clock: MutableClock,
    case: tuple[str, bool, str | None, bool],
) -> None:
    email, verified, hosted_domain, creates = case
    store = MemoryAuthStore()
    harness = create_harness(settings, store, clock, mode=GoogleAccountMode.OPEN)
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add(
        "open-token",
        claims(email=email, verified=verified, hosted_domain=hosted_domain),
    )

    if not creates:
        with pytest.raises(AuthError):
            await harness.google.finish_login(options.challenge_id, "open-token", ORIGIN)
        assert store.users == {}
        return

    session = await harness.google.finish_login(options.challenge_id, "open-token", ORIGIN)
    user = store.users[session.principal.user_id]
    assert user.roles == (harness.settings.default_user_role,)
    assert user.scopes == ()
    assert user.must_change_password is False
    assert user.password_login_enabled is False
    assert user.google_auto_link_allowed is False


@pytest.mark.asyncio
async def test_open_mode_never_seizes_an_existing_unlinked_email(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock, mode=GoogleAccountMode.OPEN)
    local = await harness.auth.create_user(email="person@gmail.com", display_name="Existing")
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("collision", claims())

    with pytest.raises(AuthError):
        await harness.google.finish_login(options.challenge_id, "collision", ORIGIN)

    assert store.users[local.user.id].password_login_enabled is True
    assert store.external_identities == {}


@pytest.mark.asyncio
async def test_google_issuer_is_canonicalized_before_identity_storage(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock, mode=GoogleAccountMode.OPEN)
    options = await harness.google.begin_login(ORIGIN)
    harness.verifier.add("issuer-token", claims(issuer="accounts.google.com"))

    await harness.google.finish_login(options.challenge_id, "issuer-token", ORIGIN)

    identity = next(iter(store.external_identities.values()))
    assert identity.issuer == GOOGLE_ISSUER
