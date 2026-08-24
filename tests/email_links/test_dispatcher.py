from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import FastAPI

from epok_auth.config import AuthSettings, Environment
from epok_auth.email_links.mailer import EmailLinkMailer
from epok_auth.email_links.models import AuthEmail, EmailLinkState, PendingEmailLink
from epok_auth.fastapi import EpokAuth
from epok_auth.models import SecurityEventType, UserAccount
from epok_auth.service import AuthService
from epok_auth.testing import MemoryAuthStore
from tests.conftest import NEW_PASSWORD, MutableClock

ORIGIN = "http://localhost:3000"


class CapturingSender:
    def __init__(self) -> None:
        self.emails: list[AuthEmail] = []

    async def send(self, email: AuthEmail) -> None:
        self.emails.append(email)


class CapturingDispatcher:
    def __init__(self, *, fail_notices: bool = False) -> None:
        self.pending: list[PendingEmailLink] = []
        self.notices: list[AuthEmail] = []
        self.fail_notices = fail_notices

    async def dispatch(self, message: AuthEmail | PendingEmailLink) -> None:
        if isinstance(message, PendingEmailLink):
            self.pending.append(message)
        else:
            if self.fail_notices:
                raise RuntimeError(f"provider leaked {message.recipient}")
            self.notices.append(message)


class FailingDispatcher:
    async def dispatch(self, message: AuthEmail | PendingEmailLink) -> None:
        secret = (
            message.email.action_url if isinstance(message, PendingEmailLink) else message.recipient
        )
        raise RuntimeError(f"queue leaked {secret}")


@pytest.fixture
def email_settings(settings: AuthSettings) -> AuthSettings:
    return settings.model_copy(
        update={
            "email_link_login_url": f"{ORIGIN}/login",
            "email_link_password_reset_url": f"{ORIGIN}/reset-password",
            "email_link_invitation_url": f"{ORIGIN}/invitation",
        }
    )


async def enabled_user(
    auth: AuthService,
    store: MemoryAuthStore,
    email: str,
) -> UserAccount:
    provisioned = await auth.create_user(email=email, display_name="Person")
    async with store.transaction() as transaction:
        await transaction.update_user(
            replace(
                provisioned.user,
                must_change_password=False,
                email_link_login_enabled=True,
            )
        )
    return provisioned.user


def token_from(email: AuthEmail) -> str:
    assert email.action_url is not None
    return parse_qs(urlsplit(email.action_url).fragment)["token"][0]


@pytest.mark.security
async def test_durable_dispatch_keeps_link_pending_until_worker_delivery(
    email_settings: AuthSettings,
    clock: MutableClock,
) -> None:
    store = MemoryAuthStore()
    auth = AuthService(store=store, settings=email_settings, clock=clock)
    user = await enabled_user(auth, store, "queued@example.com")
    sender = CapturingSender()
    dispatcher = CapturingDispatcher()
    facade = EpokAuth(
        settings=email_settings,
        store=store,
        service=auth,
        email_link_sender=sender,
        email_link_dispatcher=dispatcher,
    )
    app = FastAPI()
    facade.install(app, include_email_links=True)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            "/auth/email-links/login",
            json={"email": user.email},
            headers={"Origin": ORIGIN},
        )

    assert response.status_code == 202
    assert sender.emails == []
    pending = dispatcher.pending[0]
    assert store.email_links[pending.link_id].state is EmailLinkState.PENDING
    assert facade.email_link_service is not None
    assert await EmailLinkMailer(facade.email_link_service, sender).deliver(pending) is True
    assert store.email_links[pending.link_id].state is EmailLinkState.ACTIVE


def test_production_email_links_require_durable_dispatcher(
    email_settings: AuthSettings,
    store: MemoryAuthStore,
) -> None:
    production = AuthSettings.model_validate(
        {
            **email_settings.model_dump(),
            "environment": Environment.PRODUCTION,
            "database_url": "postgresql://user:password@db/auth",
            "issuer": "private-product-auth",
            "audience": "private-product-api",
            "secure_cookies": True,
            "cookie_use_host_prefix": True,
            "trusted_origins": ("https://app.example.com",),
            "email_link_login_url": "https://app.example.com/login",
            "email_link_password_reset_url": "https://app.example.com/reset-password",
            "email_link_invitation_url": "https://app.example.com/invitation",
        }
    )
    facade = EpokAuth(settings=production, store=store, email_link_sender=CapturingSender())

    with pytest.raises(ValueError, match="durable email_link_dispatcher"):
        facade.install(FastAPI(), include_email_links=True)

    ready = EpokAuth(
        settings=production,
        store=store,
        email_link_dispatcher=CapturingDispatcher(),
    )
    ready.install(FastAPI(), include_email_links=True)


@pytest.mark.security
async def test_dispatch_failure_is_generic_audited_and_never_logs_secrets(
    email_settings: AuthSettings,
    clock: MutableClock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = MemoryAuthStore()
    auth = AuthService(store=store, settings=email_settings, clock=clock)
    user = await enabled_user(auth, store, "queue-down@example.com")
    facade = EpokAuth(
        settings=email_settings,
        store=store,
        service=auth,
        email_link_dispatcher=FailingDispatcher(),
    )
    app = FastAPI()
    facade.install(app, include_email_links=True)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        existing = await client.post(
            "/auth/email-links/login",
            json={"email": user.email},
            headers={"Origin": ORIGIN},
        )
        unknown = await client.post(
            "/auth/email-links/login",
            json={"email": "unknown@example.com"},
            headers={"Origin": ORIGIN},
        )

    assert existing.status_code == unknown.status_code == 202
    assert existing.json() == unknown.json() == {"accepted": True}
    link = list(store.email_links.values())[-1]
    assert link.state is EmailLinkState.FAILED
    assert store.events[-1].event_type is SecurityEventType.EMAIL_LINK_DELIVERY_FAILED
    logs = caplog.text
    assert user.email not in logs
    assert "#token=" not in logs
    assert "queue leaked" not in logs


@pytest.mark.security
@pytest.mark.parametrize("fail_notice", [False, True])
async def test_password_change_notice_uses_the_durable_dispatcher(
    email_settings: AuthSettings,
    clock: MutableClock,
    caplog: pytest.LogCaptureFixture,
    fail_notice: bool,
) -> None:
    store = MemoryAuthStore()
    auth = AuthService(store=store, settings=email_settings, clock=clock)
    user = await enabled_user(auth, store, "reset-queue@example.com")
    dispatcher = CapturingDispatcher(fail_notices=fail_notice)
    facade = EpokAuth(
        settings=email_settings,
        store=store,
        service=auth,
        email_link_dispatcher=dispatcher,
    )
    app = FastAPI()
    facade.install(app, include_email_links=True)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        await client.post(
            "/auth/email-links/password-reset",
            json={"email": user.email},
            headers={"Origin": ORIGIN},
        )
        pending = dispatcher.pending[-1]
        assert facade.email_link_service is not None
        sender = CapturingSender()
        await EmailLinkMailer(facade.email_link_service, sender).deliver(pending)
        response = await client.post(
            "/auth/email-links/password-reset/consume",
            json={"token": token_from(sender.emails[-1]), "new_password": NEW_PASSWORD},
            headers={"Origin": ORIGIN},
        )

    assert response.status_code == 204
    if fail_notice:
        assert dispatcher.notices == []
        assert store.events[-1].event_type is SecurityEventType.EMAIL_NOTICE_DELIVERY_FAILED
        assert user.email not in caplog.text
    else:
        assert len(dispatcher.notices) == 1
        assert dispatcher.notices[0].action_url is None
