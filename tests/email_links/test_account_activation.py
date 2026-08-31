import asyncio
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

import pytest

from epok_auth.config import AuthSettings
from epok_auth.email_links import (
    AccountActivationService,
    AuthEmail,
    EmailLinkMailer,
    EmailLinkService,
)
from epok_auth.email_links.models import EmailLinkState
from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.fastapi import EpokAuth
from epok_auth.models import SecurityEventType, UserStatus, UserUpdate
from epok_auth.service import AuthService
from epok_auth.testing import MemoryAuthStore
from tests.conftest import ADMIN_PASSWORD, NEW_PASSWORD, MutableClock

ACTIVATION_URL = "http://localhost:3000/auth/activate"


class CapturingSender:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.emails: list[AuthEmail] = []

    async def send(self, email: AuthEmail) -> None:
        if self.error is not None:
            raise self.error
        self.emails.append(email)


@dataclass(slots=True)
class ActivationHarness:
    settings: AuthSettings
    store: MemoryAuthStore
    auth: AuthService
    activation: AccountActivationService
    links: EmailLinkService
    mailer: EmailLinkMailer


@pytest.fixture
def activation_settings(settings: AuthSettings) -> AuthSettings:
    return AuthSettings.model_validate(
        {
            **settings.model_dump(),
            "email_link_activation_url": ACTIVATION_URL,
            "email_link_activation_ttl_seconds": 300,
        }
    )


@pytest.fixture
def harness(
    activation_settings: AuthSettings,
    clock: MutableClock,
) -> ActivationHarness:
    store = MemoryAuthStore()
    auth = AuthService(store=store, settings=activation_settings, clock=clock)
    facade = EpokAuth(settings=activation_settings, store=store, service=auth)
    links = facade.email_links
    return ActivationHarness(
        settings=activation_settings,
        store=store,
        auth=auth,
        activation=facade.account_activation,
        links=links,
        mailer=EmailLinkMailer(links, CapturingSender()),
    )


def token_from(email: AuthEmail) -> str:
    assert email.action_url is not None
    return parse_qs(urlsplit(email.action_url).fragment)["token"][0]


@pytest.mark.security
async def test_pending_account_activates_once_with_its_first_password(
    harness: ActivationHarness,
) -> None:
    activation = await harness.activation.provision(
        email="person@example.com",
        display_name="Person",
        roles=("operator",),
    )
    token = token_from(activation.pending.email)

    assert activation.user.status is UserStatus.PENDING_ACTIVATION
    assert activation.user.password_login_enabled is False
    assert harness.store.email_links[activation.pending.link_id].state is EmailLinkState.PENDING
    assert token not in repr(activation)
    assert activation.user.password_hash not in repr(activation.user)

    with pytest.raises(AuthError) as undelivered:
        await harness.activation.activate(token, NEW_PASSWORD)
    assert undelivered.value.code is AuthErrorCode.EMAIL_LINK_INVALID

    assert await harness.mailer.deliver(activation.pending) is True
    user = await harness.activation.activate(token, NEW_PASSWORD)

    assert user.status is UserStatus.ACTIVE
    assert user.password_login_enabled is True
    assert user.security_version == activation.user.security_version + 1
    assert harness.store.sessions == {}
    assert harness.store.events[-1].event_type is SecurityEventType.ACCOUNT_ACTIVATED

    session = await harness.auth.login(user.email, NEW_PASSWORD)
    assert session.principal.user_id == user.id
    with pytest.raises(AuthError) as replay:
        await harness.activation.activate(token, NEW_PASSWORD)
    assert replay.value.code is AuthErrorCode.EMAIL_LINK_INVALID


@pytest.mark.security
async def test_pending_account_rejects_other_authentication_flows(
    harness: ActivationHarness,
) -> None:
    activation = await harness.activation.provision(
        email="pending@example.com",
        display_name="Pending",
    )

    with pytest.raises(AuthError) as password_login:
        await harness.auth.login(activation.user.email, NEW_PASSWORD)
    assert password_login.value.code is AuthErrorCode.INVALID_CREDENTIALS
    assert (await harness.links.request_login(activation.user.email)).pending is None
    assert (await harness.links.request_password_reset(activation.user.email)).pending is None
    with pytest.raises(AuthError) as invitation:
        await harness.links.invite(activation.user.id)
    assert invitation.value.code is AuthErrorCode.FORBIDDEN


@pytest.mark.security
async def test_user_updates_cannot_bypass_pending_activation(
    harness: ActivationHarness,
) -> None:
    activation = await harness.activation.provision(
        email="guarded@example.com",
        display_name="Guarded",
    )

    with pytest.raises(AuthError) as activation_bypass:
        await harness.auth.update_user(
            activation.user.id,
            UserUpdate(status=UserStatus.ACTIVE),
        )
    assert activation_bypass.value.code is AuthErrorCode.FORBIDDEN

    provisioned = await harness.auth.create_user(
        email="active@example.com",
        display_name="Active",
    )
    with pytest.raises(AuthError) as pending_bypass:
        await harness.auth.update_user(
            provisioned.user.id,
            UserUpdate(status=UserStatus.PENDING_ACTIVATION),
        )
    assert pending_bypass.value.code is AuthErrorCode.FORBIDDEN

    with pytest.raises(AuthError) as disabled_bypass:
        await harness.auth.update_user(
            activation.user.id,
            UserUpdate(status=UserStatus.DISABLED),
        )
    assert disabled_bypass.value.code is AuthErrorCode.FORBIDDEN


@pytest.mark.security
async def test_failed_delivery_requires_explicit_activation_replacement(
    harness: ActivationHarness,
) -> None:
    activation = await harness.activation.provision(
        email="retry@example.com",
        display_name="Retry",
    )
    failing_mailer = EmailLinkMailer(
        harness.links,
        CapturingSender(RuntimeError("provider unavailable")),
    )
    with pytest.raises(AuthError) as failed:
        await failing_mailer.deliver(activation.pending)
    assert failed.value.code is AuthErrorCode.EMAIL_DELIVERY_FAILED
    assert harness.store.email_links[activation.pending.link_id].state is EmailLinkState.FAILED

    replacement = await harness.activation.replace(activation.user.id)
    assert replacement.pending is not None
    assert replacement.pending.link_id != activation.pending.link_id
    await harness.mailer.deliver(replacement.pending)

    user = await harness.activation.activate(token_from(replacement.pending.email), NEW_PASSWORD)
    assert user.status is UserStatus.ACTIVE


@pytest.mark.security
async def test_duplicate_activation_provisioning_is_atomic(
    harness: ActivationHarness,
) -> None:
    await harness.activation.provision(
        email="duplicate@example.com",
        display_name="Original",
    )

    with pytest.raises(AuthError) as duplicate:
        await harness.activation.provision(
            email="duplicate@example.com",
            display_name="Duplicate",
        )

    assert duplicate.value.code is AuthErrorCode.USER_EXISTS
    assert len(harness.store.users) == 1
    assert len(harness.store.email_links) == 1


@pytest.mark.security
async def test_expired_activation_needs_an_explicit_replacement(
    harness: ActivationHarness,
    clock: MutableClock,
) -> None:
    activation = await harness.activation.provision(
        email="expired@example.com",
        display_name="Expired",
    )
    await harness.mailer.deliver(activation.pending)
    clock.advance(seconds=301)

    with pytest.raises(AuthError) as expired:
        await harness.activation.activate(token_from(activation.pending.email), NEW_PASSWORD)
    assert expired.value.code is AuthErrorCode.EMAIL_LINK_INVALID

    replacement = await harness.activation.replace(activation.user.id)
    assert replacement.pending is not None


@pytest.mark.security
async def test_initial_admin_bootstrap_is_idempotent_and_uses_generic_activation(
    harness: ActivationHarness,
) -> None:
    async def bootstrap():
        return await harness.activation.ensure_initial_admin(
            email="owner@example.com",
            display_name="Owner",
        )

    results = await asyncio.gather(bootstrap(), bootstrap())
    created = next(result for result in results if result.pending is not None)
    existing = next(result for result in results if result.pending is None)

    assert created.user.id == existing.user.id
    assert created.user.status is UserStatus.PENDING_ACTIVATION
    assert created.user.roles == (harness.settings.admin_role,)
    assert created.user.scopes == ("auth:admin",)
    assert len(harness.store.users) == 1
    assert len(harness.store.email_links) == 1

    assert created.pending is not None
    await harness.mailer.deliver(created.pending)
    activated = await harness.activation.activate(
        token_from(created.pending.email),
        ADMIN_PASSWORD,
    )
    repeated = await bootstrap()

    assert activated.status is UserStatus.ACTIVE
    assert repeated.user.id == activated.id
    assert repeated.pending is None


@pytest.mark.security
async def test_initial_admin_bootstrap_rejects_identity_conflicts(
    harness: ActivationHarness,
) -> None:
    await harness.activation.ensure_initial_admin(
        email="owner@example.com",
        display_name="Owner",
    )
    with pytest.raises(AuthError) as another_admin:
        await harness.activation.ensure_initial_admin(
            email="other@example.com",
            display_name="Other",
        )
    assert another_admin.value.code is AuthErrorCode.ADMIN_EXISTS

    other_store = MemoryAuthStore()
    other_auth = AuthService(store=other_store, settings=harness.settings)
    await other_auth.create_user(email="person@example.com", display_name="Person")
    activation = AccountActivationService(
        store=other_store,
        settings=harness.settings,
        passwords=other_auth.passwords,
        clock=other_auth.clock,
    )
    with pytest.raises(AuthError) as existing_user:
        await activation.ensure_initial_admin(
            email="person@example.com",
            display_name="Person",
        )
    assert existing_user.value.code is AuthErrorCode.USER_EXISTS


@pytest.mark.security
async def test_generic_activation_rejects_the_library_admin_role(
    harness: ActivationHarness,
) -> None:
    with pytest.raises(AuthError) as forbidden:
        await harness.activation.provision(
            email="admin@example.com",
            display_name="Admin",
            roles=(harness.settings.admin_role,),
        )

    assert forbidden.value.code is AuthErrorCode.FORBIDDEN
    assert harness.store.users == {}
