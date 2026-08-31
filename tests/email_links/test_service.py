from dataclasses import dataclass, replace
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest

import epok_auth.email_links.service as email_link_module
from epok_auth.config import AuthSettings
from epok_auth.email_links.mailer import EmailLinkMailer
from epok_auth.email_links.models import AuthEmail, AuthEmailKind, EmailLinkState
from epok_auth.email_links.service import EmailLinkService
from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.models import SecurityEventType, UserAccount, UserStatus, UserUpdate
from epok_auth.service import AuthService
from epok_auth.testing import MemoryAuthStore
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, NEW_PASSWORD, MutableClock

LOGIN_URL = "http://localhost:3000/auth/email-link"
RESET_URL = "http://localhost:3000/auth/reset-password"
INVITATION_URL = "http://localhost:3000/auth/invitation"


class CapturingSender:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.emails: list[AuthEmail] = []

    async def send(self, email: AuthEmail) -> None:
        if self.error is not None:
            raise self.error
        self.emails.append(email)


@dataclass(slots=True)
class EmailLinkHarness:
    settings: AuthSettings
    store: MemoryAuthStore
    auth: AuthService
    links: EmailLinkService
    sender: CapturingSender
    mailer: EmailLinkMailer

    async def user(
        self,
        email: str = "person@example.com",
        *,
        email_login: bool = True,
        must_change_password: bool = False,
    ) -> tuple[UserAccount, str]:
        provisioned = await self.auth.create_user(email=email, display_name="Person")
        user = replace(
            provisioned.user,
            must_change_password=must_change_password,
            email_link_login_enabled=email_login,
        )
        async with self.store.transaction() as transaction:
            await transaction.update_user(user)
        return user, provisioned.temporary_password


@pytest.fixture
def email_settings(settings: AuthSettings) -> AuthSettings:
    values = settings.model_dump()
    values.update(
        email_link_login_url=LOGIN_URL,
        email_link_password_reset_url=RESET_URL,
        email_link_invitation_url=INVITATION_URL,
        email_link_login_ttl_seconds=120,
        email_link_password_reset_ttl_seconds=180,
        email_link_invitation_ttl_seconds=300,
        email_link_request_window_seconds=60,
        email_link_retention_seconds=86400,
    )
    return AuthSettings.model_validate(values)


@pytest.fixture
def harness(
    email_settings: AuthSettings,
    clock: MutableClock,
) -> EmailLinkHarness:
    store = MemoryAuthStore()
    auth = AuthService(store=store, settings=email_settings, clock=clock)
    links = EmailLinkService(
        store=store,
        settings=email_settings,
        signer=auth.signer,
        passwords=auth.passwords,
        clock=clock,
    )
    sender = CapturingSender()
    return EmailLinkHarness(
        settings=email_settings,
        store=store,
        auth=auth,
        links=links,
        sender=sender,
        mailer=EmailLinkMailer(links, sender),
    )


def token_from(email: AuthEmail) -> str:
    assert email.action_url is not None
    values = parse_qs(urlsplit(email.action_url).fragment)
    return values["token"][0]


@pytest.mark.security
async def test_login_link_is_provider_activated_browser_bound_and_single_use(
    harness: EmailLinkHarness,
) -> None:
    user, _ = await harness.user()
    issue = await harness.links.request_login(user.email)
    assert issue.pending is not None
    assert issue.browser_nonce is not None
    assert "token" not in repr(issue)
    assert "person@example.com" not in repr(issue.pending)
    token = token_from(issue.pending.email)
    stored = harness.store.email_links[issue.pending.link_id]
    assert stored.state is EmailLinkState.PENDING
    assert token not in repr(stored)
    assert token not in stored.token_hash

    with pytest.raises(AuthError) as before_delivery:
        await harness.links.login(token, issue.browser_nonce)
    assert before_delivery.value.code is AuthErrorCode.EMAIL_LINK_INVALID
    assert harness.store.email_links[stored.id].state is EmailLinkState.PENDING

    assert await harness.mailer.deliver(issue.pending) is True
    assert harness.store.email_links[stored.id].state is EmailLinkState.ACTIVE

    with pytest.raises(AuthError) as wrong_browser:
        await harness.links.login(token, "different-browser")
    assert wrong_browser.value.code is AuthErrorCode.EMAIL_LINK_INVALID
    assert harness.store.email_links[stored.id].state is EmailLinkState.ACTIVE

    bundle = await harness.links.login(token, issue.browser_nonce)
    assert bundle.principal.user_id == user.id
    assert harness.store.email_links[stored.id].state is EmailLinkState.CONSUMED
    assert harness.store.events[-1].event_type is SecurityEventType.EMAIL_LINK_LOGIN_SUCCEEDED

    with pytest.raises(AuthError) as reused:
        await harness.links.login(token, issue.browser_nonce)
    assert reused.value.code is AuthErrorCode.EMAIL_LINK_INVALID


@pytest.mark.security
async def test_failed_replacement_keeps_previous_active_link(
    harness: EmailLinkHarness,
) -> None:
    user, _ = await harness.user()
    first = await harness.links.request_login(user.email)
    assert first.pending is not None and first.browser_nonce is not None
    await harness.mailer.deliver(first.pending)
    first_token = token_from(first.pending.email)

    second = await harness.links.request_login(user.email)
    assert second.pending is not None
    failure = AuthError(AuthErrorCode.EMAIL_DELIVERY_FAILED, "provider unavailable")
    failing_mailer = EmailLinkMailer(harness.links, CapturingSender(failure))
    with pytest.raises(AuthError) as captured:
        await failing_mailer.deliver(second.pending)
    assert captured.value.code is AuthErrorCode.EMAIL_DELIVERY_FAILED
    assert "provider unavailable" not in str(captured.value)
    assert harness.store.email_links[second.pending.link_id].state is EmailLinkState.FAILED
    assert harness.store.email_links[first.pending.link_id].state is EmailLinkState.ACTIVE

    bundle = await harness.links.login(first_token, first.browser_nonce)
    assert bundle.principal.user_id == user.id


@pytest.mark.security
async def test_newest_delivered_link_revokes_older_active_link(
    harness: EmailLinkHarness,
) -> None:
    user, _ = await harness.user()
    first = await harness.links.request_login(user.email)
    assert first.pending is not None and first.browser_nonce is not None
    await harness.mailer.deliver(first.pending)

    second = await harness.links.request_login(user.email)
    assert second.pending is not None and second.browser_nonce is not None
    await harness.mailer.deliver(second.pending)
    assert harness.store.email_links[first.pending.link_id].state is EmailLinkState.REVOKED

    with pytest.raises(AuthError):
        await harness.links.login(token_from(first.pending.email), first.browser_nonce)
    bundle = await harness.links.login(token_from(second.pending.email), second.browser_nonce)
    assert bundle.principal.user_id == user.id


@pytest.mark.security
async def test_password_reset_revokes_sessions_changes_fence_and_does_not_login(
    harness: EmailLinkHarness,
) -> None:
    user, temporary_password = await harness.user(email_login=False)
    existing = await harness.auth.login(user.email, temporary_password)
    issue = await harness.links.request_password_reset(user.email)
    assert issue.pending is not None
    await harness.mailer.deliver(issue.pending)

    notice = await harness.links.reset_password(token_from(issue.pending.email), NEW_PASSWORD)
    updated = harness.store.users[user.id]
    assert notice.action_url is None
    assert updated.security_version == user.security_version + 1
    assert updated.must_change_password is False
    assert all(session.revoked_at is not None for session in harness.store.sessions.values())
    assert len(harness.store.sessions) == 1

    provider_detail = AuthError(
        AuthErrorCode.EMAIL_DELIVERY_FAILED,
        f"provider leaked {notice.recipient}",
    )
    with pytest.raises(AuthError) as notice_failure:
        await EmailLinkMailer(
            harness.links,
            CapturingSender(provider_detail),
        ).send_notice(notice)
    assert notice_failure.value.code is AuthErrorCode.EMAIL_DELIVERY_FAILED
    assert notice.recipient not in str(notice_failure.value)
    assert harness.store.events[-1].event_type is SecurityEventType.EMAIL_NOTICE_DELIVERY_FAILED
    with pytest.raises(AuthError):
        await harness.auth.authenticate(existing.access_token)

    signed_in = await harness.auth.login(user.email, NEW_PASSWORD)
    assert signed_in.principal.user_id == user.id
    with pytest.raises(AuthError) as reused:
        await harness.links.reset_password(token_from(issue.pending.email), NEW_PASSWORD)
    assert reused.value.code is AuthErrorCode.EMAIL_LINK_INVALID


@pytest.mark.security
async def test_invitation_activates_passwordless_account_without_a_session(
    harness: EmailLinkHarness,
) -> None:
    user, _ = await harness.user(email_login=False, must_change_password=True)
    issue = await harness.links.invite(user.id)
    assert issue.pending is not None
    await harness.mailer.deliver(issue.pending)

    activated = await harness.links.activate_invitation(token_from(issue.pending.email))
    assert activated.password_login_enabled is False
    assert activated.email_link_login_enabled is True
    assert activated.must_change_password is False
    assert activated.security_version == user.security_version + 1
    assert harness.store.sessions == {}

    login_issue = await harness.links.request_login(user.email)
    assert login_issue.pending is not None and login_issue.browser_nonce is not None
    await harness.mailer.deliver(login_issue.pending)
    bundle = await harness.links.login(
        token_from(login_issue.pending.email),
        login_issue.browser_nonce,
    )
    assert bundle.principal.user_id == user.id


@pytest.mark.security
async def test_unknown_admin_disabled_and_opted_out_accounts_are_indistinguishable(
    harness: EmailLinkHarness,
) -> None:
    admin = await harness.auth.create_admin(
        email=ADMIN_EMAIL,
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    user, _ = await harness.user(email_login=False)
    disabled = await harness.user(email="disabled@example.com")
    await harness.auth.update_user(disabled[0].id, UserUpdate(status=UserStatus.DISABLED))

    for email in ("missing@example.com", admin.email, user.email, disabled[0].email):
        issue = await harness.links.request_login(email)
        assert issue.pending is None
        assert issue.browser_nonce is not None

    with pytest.raises(AuthError) as administrative_invitation:
        await harness.links.invite(admin.id)
    assert administrative_invitation.value.code is AuthErrorCode.FORBIDDEN


async def test_persistent_rate_limit_and_security_version_fence(
    harness: EmailLinkHarness,
) -> None:
    user, _ = await harness.user()
    issues = [await harness.links.request_login(user.email) for _ in range(4)]
    assert [issue.pending is not None for issue in issues] == [True, True, True, False]
    pending = issues[2].pending
    assert pending is not None

    updated = await harness.auth.update_user(user.id, UserUpdate(scopes=("profile:read",)))
    assert updated.security_version == user.security_version + 1
    assert await harness.links.mark_delivered(pending.link_id) is False
    assert harness.store.email_links[pending.link_id].state is EmailLinkState.REVOKED


async def test_expiry_missing_delivery_and_invalid_invitation_paths(
    harness: EmailLinkHarness,
    clock: MutableClock,
) -> None:
    assert await harness.links.mark_delivered(uuid4()) is False
    await harness.links.mark_delivery_failed(uuid4())

    user, _ = await harness.user()
    with pytest.raises(AuthError) as ineligible:
        await harness.links.invite(user.id)
    assert ineligible.value.code is AuthErrorCode.FORBIDDEN
    with pytest.raises(AuthError) as missing:
        await harness.links.invite(uuid4())
    assert missing.value.code is AuthErrorCode.USER_NOT_FOUND

    issue = await harness.links.request_login(user.email)
    assert issue.pending is not None and issue.browser_nonce is not None
    await harness.mailer.deliver(issue.pending)
    clock.advance(seconds=harness.settings.email_link_login_ttl_seconds + 1)
    with pytest.raises(AuthError):
        await harness.links.login(token_from(issue.pending.email), issue.browser_nonce)
    assert harness.store.email_links[issue.pending.link_id].state is EmailLinkState.REVOKED

    with pytest.raises(AuthError) as invalid_invitation:
        await harness.links.activate_invitation("not-an-invitation")
    assert invalid_invitation.value.code is AuthErrorCode.EMAIL_LINK_INVALID


@pytest.mark.security
async def test_invalid_tokens_and_active_security_fence(
    harness: EmailLinkHarness,
) -> None:
    user, _ = await harness.user()
    for token in ("", "x" * (harness.settings.email_link_max_token_chars + 1), "unknown"):
        with pytest.raises(AuthError) as captured:
            await harness.links.login(token, "browser")
        assert captured.value.code is AuthErrorCode.EMAIL_LINK_INVALID

    issue = await harness.links.request_login(user.email)
    assert issue.pending is not None and issue.browser_nonce is not None
    await harness.mailer.deliver(issue.pending)
    await harness.auth.update_user(user.id, UserUpdate(email_link_login_enabled=False))

    with pytest.raises(AuthError):
        await harness.links.login(token_from(issue.pending.email), issue.browser_nonce)
    assert harness.store.email_links[issue.pending.link_id].state is EmailLinkState.REVOKED


async def test_login_rejects_missing_browser_binding_without_consuming_link(
    harness: EmailLinkHarness,
) -> None:
    user, _ = await harness.user()
    issue = await harness.links.request_login(user.email)
    assert issue.pending is not None and issue.browser_nonce is not None
    await harness.mailer.deliver(issue.pending)
    stored = harness.store.email_links[issue.pending.link_id]
    harness.store.email_links[stored.id] = replace(stored, browser_hash=None)

    with pytest.raises(AuthError):
        await harness.links.login(token_from(issue.pending.email), issue.browser_nonce)
    assert harness.store.email_links[stored.id].state is EmailLinkState.ACTIVE


async def test_delivery_fails_closed_when_link_disappears_during_lock(
    harness: EmailLinkHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user, _ = await harness.user()
    issue = await harness.links.request_login(user.email)
    assert issue.pending is not None
    from epok_auth.testing import memory

    original = memory._MemoryTransaction.get_email_link
    calls = 0

    async def disappear_on_lock(transaction, link_id, *, for_update=False):
        nonlocal calls
        calls += 1
        if calls == 2:
            return None
        return await original(transaction, link_id, for_update=for_update)

    monkeypatch.setattr(memory._MemoryTransaction, "get_email_link", disappear_on_lock)
    assert await harness.links.mark_delivered(issue.pending.link_id) is False


async def test_delivery_fails_closed_when_atomic_activation_loses_race(
    harness: EmailLinkHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user, _ = await harness.user()
    issue = await harness.links.request_login(user.email)
    assert issue.pending is not None
    from epok_auth.testing import memory

    async def lose_activation(transaction, link_id, now):
        del transaction, link_id, now

    monkeypatch.setattr(memory._MemoryTransaction, "activate_email_link", lose_activation)
    assert await harness.links.mark_delivered(issue.pending.link_id) is False


async def test_invitation_fails_closed_when_atomic_consumption_loses_race(
    harness: EmailLinkHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user, _ = await harness.user(email_login=False, must_change_password=True)
    issue = await harness.links.invite(user.id)
    assert issue.pending is not None
    await harness.mailer.deliver(issue.pending)
    from epok_auth.testing import memory

    async def lose_consumption(transaction, link_id, purpose, now):
        del transaction, link_id, purpose, now

    monkeypatch.setattr(memory._MemoryTransaction, "consume_email_link", lose_consumption)
    with pytest.raises(AuthError) as captured:
        await harness.links.activate_invitation(token_from(issue.pending.email))
    assert captured.value.code is AuthErrorCode.EMAIL_LINK_INVALID


@pytest.mark.security
async def test_unknown_recovery_tokens_do_not_trigger_password_hashing(
    harness: EmailLinkHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_hash(password: str) -> str:
        del password
        raise AssertionError("invalid email-link tokens must not consume Argon2 work")

    monkeypatch.setattr(harness.links.passwords, "hash", unexpected_hash)
    with pytest.raises(AuthError) as reset:
        await harness.links.reset_password("unknown", NEW_PASSWORD)
    with pytest.raises(AuthError) as invitation:
        await harness.links.activate_invitation("unknown")

    assert reset.value.code is AuthErrorCode.EMAIL_LINK_INVALID
    assert invitation.value.code is AuthErrorCode.EMAIL_LINK_INVALID

    with pytest.raises(AuthError) as empty:
        await harness.links.reset_password("", NEW_PASSWORD)
    assert empty.value.code is AuthErrorCode.EMAIL_LINK_INVALID


async def test_recovery_revalidates_account_eligibility_after_preflight(
    harness: EmailLinkHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny_request(*args) -> bool:
        del args
        return False

    reset_user, _ = await harness.user(email="reset-race@example.com", email_login=False)
    reset_issue = await harness.links.request_password_reset(reset_user.email)
    assert reset_issue.pending is not None
    await harness.mailer.deliver(reset_issue.pending)
    with monkeypatch.context() as patch:
        patch.setattr(
            email_link_module,
            "can_request",
            deny_request,
        )
        with pytest.raises(AuthError):
            await harness.links.reset_password(token_from(reset_issue.pending.email), NEW_PASSWORD)

    invited, _ = await harness.user(
        email="invitation-race@example.com",
        email_login=False,
        must_change_password=True,
    )
    invitation = await harness.links.invite(invited.id)
    assert invitation.pending is not None
    await harness.mailer.deliver(invitation.pending)
    with monkeypatch.context() as patch:
        patch.setattr(
            email_link_module,
            "can_request",
            deny_request,
        )
        with pytest.raises(AuthError):
            await harness.links.activate_invitation(token_from(invitation.pending.email))


async def test_password_reset_fails_closed_when_atomic_consumption_loses_race(
    harness: EmailLinkHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user, _ = await harness.user(email_login=False)
    issue = await harness.links.request_password_reset(user.email)
    assert issue.pending is not None
    await harness.mailer.deliver(issue.pending)
    from epok_auth.testing import memory

    async def lose_consumption(transaction, link_id, purpose, now):
        del transaction, link_id, purpose, now

    monkeypatch.setattr(memory._MemoryTransaction, "consume_email_link", lose_consumption)
    with pytest.raises(AuthError) as captured:
        await harness.links.reset_password(token_from(issue.pending.email), NEW_PASSWORD)
    assert captured.value.code is AuthErrorCode.EMAIL_LINK_INVALID


def test_service_requires_at_least_one_frontend_url(
    settings: AuthSettings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    auth = AuthService(store=store, settings=settings, clock=clock)
    with pytest.raises(ValueError, match="frontend URL"):
        EmailLinkService(
            store=store,
            settings=settings,
            signer=auth.signer,
            passwords=auth.passwords,
            clock=clock,
        )

    activation_settings = settings.model_copy(
        update={"email_link_activation_url": "http://localhost:3000/auth/activate"}
    )
    service = EmailLinkService(
        store=store,
        settings=activation_settings,
        signer=auth.signer,
        passwords=auth.passwords,
        clock=clock,
    )
    assert service.settings is activation_settings


async def test_naive_clock_is_rejected(harness: EmailLinkHarness) -> None:
    harness.links.clock = lambda: harness.auth.clock().replace(tzinfo=None)
    with pytest.raises(ValueError, match="timezone-aware"):
        await harness.links.request_login("person@example.com")


async def test_unattributed_notice_failure_is_sanitized(harness: EmailLinkHarness) -> None:
    provider_error = RuntimeError("provider leaked person@example.com")
    notice = AuthEmail(
        recipient="person@example.com",
        kind=AuthEmailKind.PASSWORD_CHANGED,
    )

    with pytest.raises(AuthError) as captured:
        await EmailLinkMailer(
            harness.links,
            CapturingSender(provider_error),
        ).send_notice(notice)

    assert captured.value.code is AuthErrorCode.EMAIL_DELIVERY_FAILED
    assert "person@example.com" not in str(captured.value)
