from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from epok_auth.errors import AuthError, AuthErrorCode, forbidden, invalid_csrf, invalid_session
from epok_auth.google.models import (
    GOOGLE_ISSUER,
    ExternalIdentity,
    GoogleChallenge,
    GoogleChallengePurpose,
)
from epok_auth.models import (
    Principal,
    RefreshSession,
    RequestContext,
    SecurityEvent,
    SecurityEventType,
    UserAccount,
    UserStatus,
)
from epok_auth.store import StoreConflictError
from epok_auth.testing import MemoryAuthStore

NOW = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)


def user(email: str = "user@example.com") -> UserAccount:
    return UserAccount(
        id=uuid4(),
        email=email,
        display_name="User",
        password_hash="hidden",
        created_at=NOW,
        updated_at=NOW,
    )


def session(account: UserAccount, token: str = "a" * 64) -> RefreshSession:
    return RefreshSession(
        id=uuid4(),
        user_id=account.id,
        family_id=uuid4(),
        token_hash=token,
        csrf_hash="b" * 64,
        created_at=NOW,
        idle_expires_at=NOW + timedelta(minutes=10),
        absolute_expires_at=NOW + timedelta(hours=1),
        authenticated_at=NOW,
    )


def test_error_helpers_are_safe_and_stable() -> None:
    assert str(AuthError(AuthErrorCode.CONFIG_INVALID, "safe")) == "safe"
    assert invalid_session().headers == {"WWW-Authenticate": "Bearer"}
    assert invalid_csrf().status_code == 403
    assert forbidden("denied").detail == "denied"


def test_principal_capability_helpers() -> None:
    principal = Principal(
        user_id=uuid4(),
        session_id=uuid4(),
        family_id=uuid4(),
        email="user@example.com",
        display_name="User",
        roles=("editor",),
        scopes=("catalog:read",),
        must_change_password=False,
        authenticated_at=NOW,
    )
    assert principal.has_role("editor")
    assert not principal.has_role("admin")
    assert principal.has_scope("catalog:read")


def test_user_authentication_policy_is_owned_by_the_user_model() -> None:
    account = user()

    assert account.can_authenticate(NOW)
    assert not replace(account, status=UserStatus.DISABLED).can_authenticate(NOW)
    assert not replace(account, locked_until=NOW + timedelta(seconds=1)).can_authenticate(NOW)
    assert replace(account, locked_until=NOW).can_authenticate(NOW)


def test_user_security_version_advances_immutably() -> None:
    account = user()
    changed_at = NOW + timedelta(minutes=1)

    updated = account.advance_security_version(changed_at)

    assert account.security_version == 0
    assert updated.security_version == 1
    assert updated.updated_at == changed_at


@pytest.mark.parametrize(
    ("transition", "must_change_password", "password_login_enabled", "email_link_login_enabled"),
    [
        ("require_password_change", True, True, False),
        ("activate_password", False, True, False),
        ("disable_password", False, False, False),
        ("activate_email_link_login", False, False, True),
    ],
)
def test_user_password_transitions_reset_credential_state(
    transition: str,
    must_change_password: bool,
    password_login_enabled: bool,
    email_link_login_enabled: bool,
) -> None:
    account = replace(
        user(),
        google_auto_link_allowed=True,
        failed_login_attempts=4,
        locked_until=NOW + timedelta(minutes=5),
    )
    changed_at = NOW + timedelta(minutes=1)

    updated = getattr(account, transition)("new-hash", changed_at)

    assert updated.password_hash == "new-hash"
    assert updated.must_change_password is must_change_password
    assert updated.password_login_enabled is password_login_enabled
    assert updated.email_link_login_enabled is email_link_login_enabled
    assert updated.google_auto_link_allowed is False
    assert updated.failed_login_attempts == 0
    assert updated.locked_until is None
    assert updated.security_version == account.security_version + 1
    assert updated.password_changed_at == changed_at
    assert updated.updated_at == changed_at


def test_refresh_session_owns_subject_and_expiry_validation() -> None:
    account = user()
    credential = session(account)
    principal = Principal(
        user_id=account.id,
        session_id=credential.id,
        family_id=credential.family_id,
        email=account.email,
        display_name=account.display_name,
        roles=(),
        scopes=(),
        must_change_password=False,
        authenticated_at=NOW,
    )

    assert credential.is_active(NOW)
    assert credential.is_valid_for(principal, NOW)
    assert not replace(credential, revoked_at=NOW).is_valid_for(principal, NOW)
    assert not replace(credential, idle_expires_at=NOW).is_valid_for(principal, NOW)
    assert not replace(credential, absolute_expires_at=NOW).is_valid_for(principal, NOW)
    assert not credential.is_valid_for(replace(principal, session_id=uuid4()), NOW)
    assert not credential.is_valid_for(replace(principal, family_id=uuid4()), NOW)
    assert not credential.is_valid_for(
        replace(principal, authenticated_at=NOW + timedelta(seconds=2)),
        NOW,
    )


def test_security_event_factory_bounds_untrusted_request_metadata() -> None:
    metadata = {"reason": "invalid"}
    event = SecurityEvent.from_request(
        SecurityEventType.LOGIN_FAILED,
        NOW,
        context=RequestContext(
            request_id="r" * 201,
            ip_address="i" * 65,
            user_agent="u" * 501,
        ),
        metadata=metadata,
    )
    metadata["reason"] = "changed"

    assert event.request_id == "r" * 200
    assert event.ip_address == "i" * 64
    assert event.user_agent == "u" * 500
    assert event.metadata == {"reason": "invalid"}


@pytest.mark.asyncio
async def test_memory_transaction_rolls_back_every_collection() -> None:
    store = MemoryAuthStore()
    account = user()
    credential = session(account)
    with pytest.raises(RuntimeError):
        async with store.transaction() as transaction:
            await transaction.insert_user(account)
            await transaction.insert_session(credential)
            await transaction.add_security_event(
                SecurityEvent(SecurityEventType.USER_CREATED, occurred_at=NOW, user_id=account.id)
            )
            raise RuntimeError("rollback")
    assert store.users == {}
    assert store.sessions == {}
    assert store.events == []


@pytest.mark.asyncio
async def test_memory_store_enforces_unique_users_and_sessions() -> None:
    store = MemoryAuthStore()
    first = user()
    same_email = user(first.email)
    first_session = session(first)
    same_hash = session(first, first_session.token_hash)
    async with store.transaction() as transaction:
        await transaction.insert_user(first)
        with pytest.raises(StoreConflictError):
            await transaction.insert_user(same_email)
        await transaction.insert_session(first_session)
        with pytest.raises(StoreConflictError):
            await transaction.insert_session(same_hash)


@pytest.mark.asyncio
async def test_memory_store_rejects_duplicate_email_during_update() -> None:
    store = MemoryAuthStore()
    first = user("first@example.com")
    second = user("second@example.com")

    async with store.transaction() as transaction:
        await transaction.insert_user(first)
        await transaction.insert_user(second)
        with pytest.raises(StoreConflictError):
            await transaction.update_user(replace(second, email=first.email))

    assert store.users[second.id].email == "second@example.com"


@pytest.mark.asyncio
async def test_memory_store_enforces_unique_google_challenges() -> None:
    store = MemoryAuthStore()
    challenge = GoogleChallenge(
        id=uuid4(),
        purpose=GoogleChallengePurpose.LOGIN,
        nonce="n" * 32,
        origin="http://localhost:3000",
        client_id="123456789-test.apps.googleusercontent.com",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )

    async with store.transaction() as transaction:
        await transaction.insert_google_challenge(challenge)
        with pytest.raises(StoreConflictError):
            await transaction.insert_google_challenge(replace(challenge, id=uuid4()))


@pytest.mark.asyncio
async def test_memory_store_enforces_external_identity_contract() -> None:
    store = MemoryAuthStore()
    account = user()
    identity = ExternalIdentity(
        id=uuid4(),
        user_id=account.id,
        issuer=GOOGLE_ISSUER,
        subject="google-subject",
        email=account.email,
        created_at=NOW,
    )

    async with store.transaction() as transaction:
        await transaction.insert_user(account)
        await transaction.insert_external_identity(identity)
        with pytest.raises(StoreConflictError):
            await transaction.insert_external_identity(replace(identity, id=uuid4()))
        with pytest.raises(KeyError):
            await transaction.update_external_identity(
                replace(identity, id=uuid4(), subject="missing-subject")
            )
        with pytest.raises(KeyError):
            await transaction.delete_external_identity(uuid4())


@pytest.mark.asyncio
async def test_memory_updates_missing_objects_and_revokes_idempotently() -> None:
    store = MemoryAuthStore()
    account = user()
    credential = session(account)
    async with store.transaction() as transaction:
        with pytest.raises(KeyError):
            await transaction.update_user(account)
        with pytest.raises(KeyError):
            await transaction.update_session(credential)
        await transaction.insert_user(account)
        await transaction.insert_session(credential)
        await transaction.update_user(replace(account, display_name="Updated"))
        await transaction.update_session(replace(credential, used_at=NOW, replaced_by_id=uuid4()))
        assert await transaction.revoke_family(credential.family_id, revoked_at=NOW) == 1
        assert await transaction.revoke_family(credential.family_id, revoked_at=NOW) == 0
        assert await transaction.revoke_user_sessions(account.id, revoked_at=NOW) == 0
