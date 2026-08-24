from dataclasses import dataclass, replace
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import FastAPI, Response

from epok_auth.config import AuthSettings
from epok_auth.email_links.mailer import EmailLinkMailer
from epok_auth.email_links.models import AuthEmail, PendingEmailLink
from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.fastapi import EpokAuth
from epok_auth.fastapi.transport import AuthHttpTransport
from epok_auth.models import UserAccount
from epok_auth.service import AuthService
from epok_auth.testing import MemoryAuthStore
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, NEW_PASSWORD, MutableClock

ORIGIN = "http://localhost:3000"
PREFIX = "/api/v1/auth"


class CapturingSender:
    def __init__(self) -> None:
        self.emails: list[AuthEmail] = []

    async def send(self, email: AuthEmail) -> None:
        self.emails.append(email)


class CapturingDispatcher:
    def __init__(self) -> None:
        self.pending: list[PendingEmailLink] = []
        self.notices: list[AuthEmail] = []

    async def dispatch(self, message: AuthEmail | PendingEmailLink) -> None:
        if isinstance(message, PendingEmailLink):
            self.pending.append(message)
        else:
            self.notices.append(message)


@dataclass(slots=True)
class HttpHarness:
    settings: AuthSettings
    store: MemoryAuthStore
    auth: AuthService
    facade: EpokAuth
    sender: CapturingSender
    app: FastAPI

    def client(self) -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=self.app)
        return httpx.AsyncClient(transport=transport, base_url="http://testserver")

    async def user(
        self,
        email: str = "person@example.com",
        *,
        must_change_password: bool = False,
        email_login: bool = True,
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
        email_link_login_url=f"{ORIGIN}/login",
        email_link_password_reset_url=f"{ORIGIN}/reset-password",
        email_link_invitation_url=f"{ORIGIN}/invitation",
    )
    return AuthSettings.model_validate(values)


@pytest.fixture
def harness(email_settings: AuthSettings, clock: MutableClock) -> HttpHarness:
    store = MemoryAuthStore()
    auth = AuthService(store=store, settings=email_settings, clock=clock)
    sender = CapturingSender()
    facade = EpokAuth(
        settings=email_settings,
        store=store,
        service=auth,
        email_link_sender=sender,
    )
    app = FastAPI()
    facade.install(
        app,
        prefix=PREFIX,
        include_admin=True,
        include_email_links=True,
    )
    return HttpHarness(email_settings, store, auth, facade, sender, app)


def token_from(email: AuthEmail) -> str:
    assert email.action_url is not None
    return parse_qs(urlsplit(email.action_url).fragment)["token"][0]


@pytest.mark.security
async def test_magic_login_http_flow_is_generic_cookie_bound_and_uncached(
    harness: HttpHarness,
) -> None:
    user, _ = await harness.user()
    async with harness.client() as client:
        response = await client.post(
            f"{PREFIX}/email-links/login",
            json={"email": user.email},
            headers={"Origin": ORIGIN},
        )
        assert response.status_code == 202
        assert response.json() == {"accepted": True}
        assert response.headers["cache-control"] == "no-store"
        cookie = response.headers["set-cookie"]
        assert "epok_email_link=" in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=lax" in cookie
        assert len(harness.sender.emails) == 1

        token = token_from(harness.sender.emails[-1])
        consumed = await client.post(
            f"{PREFIX}/email-links/login/consume",
            json={"token": token},
            headers={"Origin": ORIGIN},
        )
        assert consumed.status_code == 200
        assert consumed.json()["user"]["email"] == user.email
        assert consumed.headers["cache-control"] == "no-store"
        cookies = consumed.headers.get_list("set-cookie")
        assert any("epok_refresh=" in item for item in cookies)
        assert any("epok_csrf=" in item for item in cookies)
        assert any("epok_email_link=" in item and "Max-Age=0" in item for item in cookies)

        me = await client.get(
            f"{PREFIX}/me",
            headers={"Authorization": f"Bearer {consumed.json()['access_token']}"},
        )
        assert me.status_code == 200


@pytest.mark.security
async def test_unknown_and_ineligible_login_requests_keep_the_same_public_contract(
    harness: HttpHarness,
) -> None:
    opted_out, _ = await harness.user(email_login=False)
    async with harness.client() as client:
        unknown = await client.post(
            f"{PREFIX}/email-links/login",
            json={"email": "unknown@example.com"},
            headers={"Origin": ORIGIN},
        )
        opted_out_response = await client.post(
            f"{PREFIX}/email-links/login",
            json={"email": opted_out.email},
            headers={"Origin": ORIGIN},
        )

    for response in (unknown, opted_out_response):
        assert response.status_code == 202
        assert response.json() == {"accepted": True}
        assert response.headers["cache-control"] == "no-store"
        assert "epok_email_link=" in response.headers["set-cookie"]
    assert harness.sender.emails == []

    async with harness.client() as client:
        reset = await client.post(
            f"{PREFIX}/email-links/password-reset",
            json={"email": "unknown@example.com"},
            headers={"Origin": ORIGIN},
        )
    assert reset.status_code == 202
    assert reset.json() == {"accepted": True}
    assert harness.sender.emails == []


@pytest.mark.security
async def test_password_reset_http_flow_never_creates_a_session(
    harness: HttpHarness,
) -> None:
    user, _ = await harness.user(email_login=False)
    async with harness.client() as client:
        requested = await client.post(
            f"{PREFIX}/email-links/password-reset",
            json={"email": user.email},
            headers={"Origin": ORIGIN},
        )
        assert requested.status_code == 202
        reset_email = harness.sender.emails[-1]

        reset = await client.post(
            f"{PREFIX}/email-links/password-reset/consume",
            json={"token": token_from(reset_email), "new_password": NEW_PASSWORD},
            headers={"Origin": ORIGIN},
        )
        assert reset.status_code == 204
        assert "epok_refresh" not in reset.headers.get("set-cookie", "")
        assert harness.sender.emails[-1].action_url is None

        replay = await client.post(
            f"{PREFIX}/email-links/password-reset/consume",
            json={"token": token_from(reset_email), "new_password": NEW_PASSWORD},
            headers={"Origin": ORIGIN},
        )
        assert replay.status_code == 400
        assert replay.json()["code"] == "AUTH_EMAIL_LINK_INVALID"

        login = await client.post(
            f"{PREFIX}/login",
            json={"email": user.email, "password": NEW_PASSWORD},
            headers={"Origin": ORIGIN},
        )
        assert login.status_code == 200


@pytest.mark.security
async def test_admin_invitation_activates_without_logging_in(
    harness: HttpHarness,
) -> None:
    await harness.auth.create_admin(
        email=ADMIN_EMAIL,
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    invited, _ = await harness.user(
        email="invited@example.com",
        must_change_password=True,
        email_login=False,
    )
    async with harness.client() as admin_client:
        login = await admin_client.post(
            f"{PREFIX}/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
            headers={"Origin": ORIGIN},
        )
        invitation = await admin_client.post(
            f"{PREFIX}/users/{invited.id}/invitation",
            headers={
                "Authorization": f"Bearer {login.json()['access_token']}",
                "Origin": ORIGIN,
            },
        )
        assert invitation.status_code == 202
        invitation_email = harness.sender.emails[-1]

    async with harness.client() as invited_client:
        activated = await invited_client.post(
            f"{PREFIX}/email-links/invitation/consume",
            json={"token": token_from(invitation_email)},
            headers={"Origin": ORIGIN},
        )
        assert activated.status_code == 204
        assert "set-cookie" not in activated.headers

    stored = harness.store.users[invited.id]
    assert stored.email_link_login_enabled is True
    assert stored.password_login_enabled is False
    assert all(session.user_id != invited.id for session in harness.store.sessions.values())


@pytest.mark.security
async def test_consumption_requires_trusted_origin_and_signed_out_browser(
    harness: HttpHarness,
) -> None:
    user, password = await harness.user()
    async with harness.client() as client:
        untrusted = await client.post(
            f"{PREFIX}/email-links/login",
            json={"email": user.email},
            headers={"Origin": "https://evil.example"},
        )
        assert untrusted.status_code == 403
        assert untrusted.json()["code"] == "AUTH_ORIGIN_INVALID"

        invalid = await client.post(
            f"{PREFIX}/email-links/login",
            json={"email": "x", "extra": True},
            headers={"Origin": ORIGIN},
        )
        assert invalid.status_code == 422
        assert invalid.headers["cache-control"] == "no-store"

        requested = await client.post(
            f"{PREFIX}/email-links/login",
            json={"email": user.email},
            headers={"Origin": ORIGIN},
        )
        assert requested.status_code == 202
        token = token_from(harness.sender.emails[-1])
        bundle = await harness.auth.login(user.email, password)
        blocked_by_bearer = await client.post(
            f"{PREFIX}/email-links/login/consume",
            json={"token": token},
            headers={
                "Authorization": f"Bearer {bundle.access_token}",
                "Origin": ORIGIN,
            },
        )
        assert blocked_by_bearer.status_code == 409
        assert blocked_by_bearer.json()["code"] == "AUTH_EMAIL_LINK_SESSION_EXISTS"

        client.cookies.set(harness.settings.effective_refresh_cookie_name, "existing-session")
        blocked = await client.post(
            f"{PREFIX}/email-links/login/consume",
            json={"token": token},
            headers={"Origin": ORIGIN},
        )
        assert blocked.status_code == 409
        assert blocked.json()["code"] == "AUTH_EMAIL_LINK_SESSION_EXISTS"


def test_install_requires_email_link_frontend_urls(
    settings: AuthSettings,
    store: MemoryAuthStore,
) -> None:
    facade = EpokAuth(
        settings=settings,
        store=store,
        email_link_sender=CapturingSender(),
    )
    with pytest.raises(ValueError, match="frontend URLs"):
        facade.install(FastAPI(), include_email_links=True)


def test_email_links_install_without_administration(
    email_settings: AuthSettings,
    store: MemoryAuthStore,
) -> None:
    facade = EpokAuth(
        settings=email_settings,
        store=store,
        email_link_sender=CapturingSender(),
    )
    app = FastAPI()
    facade.install(app, include_email_links=True)
    paths = set(app.openapi()["paths"])

    assert "/auth/email-links/login" in paths
    assert not any(path.endswith("/invitation") and "{user_id}" in path for path in paths)


def test_email_link_cookie_is_always_same_site_lax(email_settings: AuthSettings) -> None:
    cross_site_sessions = email_settings.model_copy(
        update={"cookie_same_site": "none", "secure_cookies": True}
    )
    response = Response()
    transport = AuthHttpTransport(cross_site_sessions)

    transport.set_email_link_cookie(response, "browser-proof")

    assert "SameSite=lax" in response.headers["set-cookie"]


@pytest.mark.security
async def test_login_cookie_survives_failed_replacement_and_rate_limit(
    email_settings: AuthSettings,
    clock: MutableClock,
) -> None:
    store = MemoryAuthStore()
    auth = AuthService(store=store, settings=email_settings, clock=clock)
    provisioned = await auth.create_user(email="replacement@example.com", display_name="Person")
    async with store.transaction() as transaction:
        await transaction.update_user(
            replace(
                provisioned.user,
                must_change_password=False,
                email_link_login_enabled=True,
            )
        )
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
        first_response = await client.post(
            "/auth/email-links/login",
            json={"email": provisioned.user.email},
            headers={"Origin": ORIGIN},
        )
        first_cookie = client.cookies.get(email_settings.effective_email_link_cookie_name)
        first = dispatcher.pending[-1]
        assert facade.email_link_service is not None
        mailer = EmailLinkMailer(facade.email_link_service, sender)
        await mailer.deliver(first)

        await client.post(
            "/auth/email-links/login",
            json={"email": provisioned.user.email},
            headers={"Origin": ORIGIN},
        )
        second = dispatcher.pending[-1]
        failure = RuntimeError("provider unavailable")

        class FailingSender:
            async def send(self, email: AuthEmail) -> None:
                del email
                raise failure

        with pytest.raises(AuthError) as delivery:
            await EmailLinkMailer(facade.email_link_service, FailingSender()).deliver(second)
        assert delivery.value.code is AuthErrorCode.EMAIL_DELIVERY_FAILED
        assert "provider unavailable" not in str(delivery.value)

        await client.post(
            "/auth/email-links/login",
            json={"email": provisioned.user.email},
            headers={"Origin": ORIGIN},
        )
        limited = await client.post(
            "/auth/email-links/login",
            json={"email": provisioned.user.email},
            headers={"Origin": ORIGIN},
        )
        assert limited.status_code == 202
        assert client.cookies.get(email_settings.effective_email_link_cookie_name) == first_cookie

        consumed = await client.post(
            "/auth/email-links/login/consume",
            json={"token": token_from(first.email)},
            headers={"Origin": ORIGIN},
        )

    assert first_response.status_code == 202
    assert consumed.status_code == 200
