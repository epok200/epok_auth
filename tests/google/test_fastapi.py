import httpx
import pytest
from fastapi import FastAPI

from epok_auth.config import AuthSettings, GoogleAccountMode
from epok_auth.fastapi import EpokAuth
from epok_auth.testing import MemoryAuthStore
from tests.conftest import MutableClock
from tests.google.fakes import CLIENT_ID, ORIGIN, GoogleHarness, claims, create_harness

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "Google HTTP tests protect private colors"


async def _client(
    settings: AuthSettings,
    clock: MutableClock,
    *,
    mode: GoogleAccountMode = GoogleAccountMode.LINKED_ONLY,
    include_admin: bool = True,
    include_google: bool = True,
) -> tuple[GoogleHarness, EpokAuth, httpx.AsyncClient]:
    store = MemoryAuthStore()
    harness = create_harness(settings, store, clock, mode=mode)
    facade = EpokAuth(
        settings=harness.settings,
        store=store,
        service=harness.auth,
        google=harness.google,
    )
    app = FastAPI()
    facade.install(
        app,
        prefix="/api/v1/auth",
        include_admin=include_admin,
        include_google=include_google,
    )
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
    return harness, facade, client


async def _admin_session(harness: GoogleHarness, client: httpx.AsyncClient) -> str:
    await harness.auth.create_admin(
        email=ADMIN_EMAIL,
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        headers={"Origin": ORIGIN},
    )
    return response.json()["access_token"]


@pytest.mark.asyncio
async def test_google_options_are_origin_bound_and_never_cached(
    settings: AuthSettings,
    clock: MutableClock,
) -> None:
    _, _, client = await _client(settings, clock)
    async with client:
        response = await client.post(
            "/api/v1/auth/google/options",
            headers={"Origin": ORIGIN},
        )
        untrusted = await client.post(
            "/api/v1/auth/google/options",
            headers={"Origin": "https://evil.example"},
        )

    assert response.status_code == 200
    assert response.json()["client_id"] == CLIENT_ID
    assert response.json()["nonce"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert untrusted.status_code == 403
    assert untrusted.json()["code"] == "AUTH_ORIGIN_INVALID"


@pytest.mark.asyncio
async def test_google_verify_creates_session_cookies_and_authenticated_principal(
    settings: AuthSettings,
    clock: MutableClock,
) -> None:
    harness, _, client = await _client(settings, clock, mode=GoogleAccountMode.OPEN)
    async with client:
        options = await client.post(
            "/api/v1/auth/google/options",
            headers={"Origin": ORIGIN},
        )
        harness.verifier.add("google-token", claims())
        response = await client.post(
            "/api/v1/auth/google/verify",
            json={
                "challenge_id": options.json()["challenge_id"],
                "credential": "google-token",
            },
            headers={"Origin": ORIGIN},
        )
        me = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {response.json()['access_token']}"},
        )

    assert response.status_code == 200
    assert response.json()["user"]["email"] == "person@gmail.com"
    assert response.headers["cache-control"] == "no-store"
    assert len(response.headers.get_list("set-cookie")) == 2
    assert me.status_code == 200
    assert me.json()["roles"] == [harness.settings.default_user_role]


@pytest.mark.asyncio
@pytest.mark.security
async def test_google_validation_never_echoes_credential_or_unknown_fields(
    settings: AuthSettings,
    clock: MutableClock,
) -> None:
    _, _, client = await _client(settings, clock)
    credential = "private-google-credential" * 1000
    async with client:
        response = await client.post(
            "/api/v1/auth/google/verify",
            json={
                "challenge_id": "not-a-uuid",
                "credential": credential,
                "unexpected": "private-extra",
            },
            headers={"Origin": ORIGIN},
        )

    assert response.status_code == 422
    assert response.json()["code"] == "AUTH_INPUT_INVALID"
    assert credential not in response.text
    assert "private-extra" not in response.text


@pytest.mark.asyncio
async def test_explicit_google_link_works_through_authenticated_http_contract(
    settings: AuthSettings,
    clock: MutableClock,
) -> None:
    harness, _, client = await _client(settings, clock)
    async with client:
        token = await _admin_session(harness, client)
        headers = {"Authorization": f"Bearer {token}", "Origin": ORIGIN}
        options = await client.post("/api/v1/auth/google/link/options", headers=headers)
        harness.verifier.add("link-token", claims(email="other@gmail.com"))
        linked = await client.post(
            "/api/v1/auth/google/link/verify",
            json={
                "challenge_id": options.json()["challenge_id"],
                "credential": "link-token",
            },
            headers=headers,
        )

    assert options.status_code == 200
    assert linked.status_code == 200
    assert linked.json()["provider"] == "google"
    assert linked.json()["email"] == "other@gmail.com"
    assert linked.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_admin_can_preauthorize_and_recover_google_account_over_http(
    settings: AuthSettings,
    clock: MutableClock,
) -> None:
    harness, _, client = await _client(settings, clock, mode=GoogleAccountMode.OPEN)
    async with client:
        admin_token = await _admin_session(harness, client)
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        created = await client.post(
            "/api/v1/auth/users",
            json={
                "email": "employee@example.com",
                "display_name": "Employee",
                "google_auto_link_allowed": True,
            },
            headers=admin_headers,
        )
        user_id = created.json()["user"]["id"]
        google_options = await client.post(
            "/api/v1/auth/google/options",
            headers={"Origin": ORIGIN},
        )
        harness.verifier.add(
            "employee-google",
            claims(email="employee@example.com", hosted_domain="example.com"),
        )
        google_login = await client.post(
            "/api/v1/auth/google/verify",
            json={
                "challenge_id": google_options.json()["challenge_id"],
                "credential": "employee-google",
            },
            headers={"Origin": ORIGIN},
        )
        recovered = await client.post(
            f"/api/v1/auth/users/{user_id}/google/recover",
            headers=admin_headers,
        )

    assert created.status_code == 201
    assert created.json()["user"]["google_auto_link_allowed"] is True
    assert google_login.status_code == 200
    assert recovered.status_code == 200
    assert recovered.json()["temporary_password"]
    assert recovered.json()["user"]["password_login_enabled"] is True
    assert recovered.json()["user"]["must_change_password"] is True
    assert recovered.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_google_routes_are_opt_in_and_openapi_contains_no_secret_claims(
    settings: AuthSettings,
    clock: MutableClock,
) -> None:
    _, facade, client = await _client(settings, clock, include_google=False)
    async with client:
        missing = await client.post(
            "/api/v1/auth/google/options",
            headers={"Origin": ORIGIN},
        )
    app = FastAPI()
    facade.install(app, prefix="/auth", include_admin=True, include_google=True)
    schema = app.openapi()

    assert missing.status_code == 404
    assert {
        "/auth/google/options",
        "/auth/google/verify",
        "/auth/google/link/options",
        "/auth/google/link/verify",
        "/auth/users/{user_id}/google/recover",
    } <= set(schema["paths"])
    assert "subject" not in str(schema).casefold()
    assert "password_hash" not in str(schema)


def test_google_install_fails_at_startup_when_client_id_is_missing(settings: AuthSettings) -> None:
    facade = EpokAuth(settings=settings, store=MemoryAuthStore())

    with pytest.raises(ValueError, match="google_client_id"):
        facade.install(FastAPI(), include_google=True)


def test_lazy_google_install_requires_explicit_store_contract(
    settings: AuthSettings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    facade = EpokAuth(
        settings=harness.settings,
        store=store,
        service=harness.auth,
    )

    with pytest.raises(ValueError, match="google_store"):
        facade.install(FastAPI(), include_google=True)


def test_lazy_google_resource_owner_cannot_be_shared_between_apps(
    settings: AuthSettings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    facade = EpokAuth(
        settings=harness.settings,
        store=store,
        service=harness.auth,
        google_store=store,
    )
    facade.install(FastAPI(), prefix="/first")

    with pytest.raises(ValueError, match="resource owner"):
        facade.install(FastAPI(), prefix="/second")


@pytest.mark.asyncio
async def test_lazy_google_install_without_admin_closes_owned_verifier(
    settings: AuthSettings,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryAuthStore()
    harness = create_harness(settings, store, clock)
    state = {"close_calls": 0}

    class Verifier:
        def __init__(self, **options: object) -> None:
            assert options

        def verify(self, credential: str, *, audience: str, nonce: str):
            raise AssertionError((credential, audience, nonce))

        def close(self) -> None:
            state["close_calls"] += 1

    import epok_auth.google.google_auth

    monkeypatch.setattr(epok_auth.google.google_auth, "GoogleAuthVerifier", Verifier)
    facade = EpokAuth(
        settings=harness.settings,
        store=store,
        service=harness.auth,
        google_store=store,
    )
    app = FastAPI()

    facade.install(app, include_google=True, include_admin=False)
    paths = set(app.openapi()["paths"])
    await facade.aclose()
    await facade.aclose()

    assert "/auth/google/options" in paths
    assert "/auth/users/{user_id}/google/recover" not in paths
    assert state["close_calls"] == 1
