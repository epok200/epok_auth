from __future__ import annotations

import httpx
import pytest
from fastapi import Depends, FastAPI

from epok_auth import AuthSettings, EpokAuth
from epok_auth.models import Principal
from epok_auth.testing import MemoryAuthStore
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, NEW_PASSWORD

ORIGIN = "http://localhost:3000"


async def client_for(
    *,
    settings: AuthSettings,
    include_admin: bool = True,
) -> tuple[EpokAuth, httpx.AsyncClient]:
    auth = EpokAuth(settings=settings, store=MemoryAuthStore())
    await auth.service.create_admin(
        email=ADMIN_EMAIL,
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    app = FastAPI()
    auth.install(app, prefix="/api/v1/auth", include_admin=include_admin)

    private = auth.protected_router(prefix="/api/v1/private")

    @private.get("")
    async def private_route(
        principal: Principal = Depends(auth.authenticated),
    ) -> dict[str, str]:
        return {"email": principal.email}

    scoped = auth.protected_router(prefix="/api/v1/write")

    @scoped.post("")
    async def write_route(
        principal: Principal = Depends(auth.require_scopes("catalog:write")),
    ) -> dict[str, str]:
        return {"email": principal.email}

    app.include_router(private)
    app.include_router(scoped)
    transport = httpx.ASGITransport(app=app)
    return auth, httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def login(client: httpx.AsyncClient, password: str = ADMIN_PASSWORD) -> httpx.Response:
    return await client.post(
        "/api/v1/auth/login",
        json={"email": ADMIN_EMAIL, "password": password},
        headers={"Origin": ORIGIN},
    )


@pytest.mark.asyncio
async def test_install_exposes_secure_contract_and_authenticates(settings: AuthSettings) -> None:
    auth, client = await client_for(settings=settings)
    async with client:
        response = await login(client)
        assert response.status_code == 200
        payload = response.json()
        assert payload["token_type"] == "bearer"
        assert payload["user"]["email"] == ADMIN_EMAIL
        assert "refresh_token" not in payload
        assert ADMIN_PASSWORD not in response.text
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"
        cookies = response.headers.get_list("set-cookie")
        assert len(cookies) == 2
        assert all("HttpOnly" in item for item in cookies)
        assert all("SameSite=lax" in item for item in cookies)
        assert all("Path=/" in item for item in cookies)

        token = payload["access_token"]
        me = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me.status_code == 200
        assert me.json()["roles"] == ["admin"]

        private = await client.get(
            "/api/v1/private",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert private.status_code == 200
        assert private.json() == {"email": ADMIN_EMAIL}

        forbidden = await client.post(
            "/api/v1/write",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert forbidden.status_code == 403
        assert forbidden.json()["code"] == "AUTH_FORBIDDEN"

    assert auth.settings is settings


@pytest.mark.asyncio
async def test_missing_or_invalid_bearer_is_uniform(settings: AuthSettings) -> None:
    _, client = await client_for(settings=settings)
    async with client:
        missing = await client.get("/api/v1/private")
        malformed = await client.get(
            "/api/v1/private",
            headers={"Authorization": "Basic bad"},
        )
        invalid = await client.get(
            "/api/v1/private",
            headers={"Authorization": "Bearer invalid"},
        )
    for response in (missing, malformed, invalid):
        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_TOKEN_INVALID"
        assert response.headers["www-authenticate"] == "Bearer"
        assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_login_validation_redacts_password(settings: AuthSettings) -> None:
    _, client = await client_for(settings=settings)
    secret = "private-value-" * 200
    async with client:
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": ADMIN_EMAIL, "password": secret, "unexpected": "field"},
            headers={"Origin": ORIGIN},
        )
    assert response.status_code == 422
    assert response.json()["code"] == "AUTH_INPUT_INVALID"
    assert secret not in response.text
    assert "unexpected" not in response.text


@pytest.mark.asyncio
async def test_refresh_rotates_cookie_and_logout_clears_it(settings: AuthSettings) -> None:
    _, client = await client_for(settings=settings)
    async with client:
        first = await login(client)
        old_refresh = client.cookies.get(settings.effective_refresh_cookie_name)
        csrf = first.json()["csrf_token"]
        refreshed = await client.post(
            "/api/v1/auth/refresh",
            headers={"Origin": ORIGIN, settings.csrf_header_name: csrf},
        )
        assert refreshed.status_code == 200
        assert client.cookies.get(settings.effective_refresh_cookie_name) != old_refresh
        assert refreshed.json()["access_token"] != first.json()["access_token"]

        new_csrf = refreshed.json()["csrf_token"]
        logout = await client.post(
            "/api/v1/auth/logout",
            headers={"Origin": ORIGIN, settings.csrf_header_name: new_csrf},
        )
        assert logout.status_code == 204
        assert client.cookies.get(settings.effective_refresh_cookie_name) is None
        assert client.cookies.get(settings.effective_csrf_cookie_name) is None
        assert logout.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_refresh_and_logout_require_csrf_and_trusted_origin(settings: AuthSettings) -> None:
    _, client = await client_for(settings=settings)
    async with client:
        first = await login(client)
        csrf = first.json()["csrf_token"]
        no_csrf = await client.post("/api/v1/auth/refresh", headers={"Origin": ORIGIN})
        assert no_csrf.status_code == 403
        assert no_csrf.json()["code"] == "AUTH_CSRF_INVALID"

        evil = await client.post(
            "/api/v1/auth/refresh",
            headers={"Origin": "https://evil.example", settings.csrf_header_name: csrf},
        )
        assert evil.status_code == 403
        assert evil.json()["code"] == "AUTH_ORIGIN_INVALID"

        missing_origin = await client.post(
            "/api/v1/auth/logout",
            headers={settings.csrf_header_name: csrf},
        )
        assert missing_origin.status_code == 403
        assert missing_origin.json()["code"] == "AUTH_ORIGIN_INVALID"


@pytest.mark.asyncio
async def test_must_change_password_can_use_me_and_change_password_only(
    settings: AuthSettings,
) -> None:
    auth, client = await client_for(settings=settings)
    provisioned = await auth.service.create_user(email="new@example.com", display_name="New")
    async with client:
        signed_in = await client.post(
            "/api/v1/auth/login",
            json={"email": "new@example.com", "password": provisioned.temporary_password},
            headers={"Origin": ORIGIN},
        )
        token = signed_in.json()["access_token"]
        me = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        blocked = await client.get(
            "/api/v1/private",
            headers={"Authorization": f"Bearer {token}"},
        )
        changed = await client.post(
            "/api/v1/auth/change-password",
            json={
                "current_password": provisioned.temporary_password,
                "new_password": NEW_PASSWORD,
            },
            headers={"Authorization": f"Bearer {token}", "Origin": ORIGIN},
        )
        assert me.status_code == 200
        assert me.json()["must_change_password"] is True
        assert blocked.status_code == 403
        assert blocked.json()["code"] == "AUTH_PASSWORD_CHANGE_REQUIRED"
        assert changed.status_code == 200
        assert changed.json()["user"]["must_change_password"] is False


@pytest.mark.asyncio
async def test_admin_router_provisions_updates_resets_and_revokes(settings: AuthSettings) -> None:
    _, client = await client_for(settings=settings)
    async with client:
        signed_in = await login(client)
        headers = {"Authorization": f"Bearer {signed_in.json()['access_token']}"}
        created = await client.post(
            "/api/v1/auth/users",
            json={
                "email": "editor@example.com",
                "display_name": "Editor",
                "roles": ["editor"],
                "scopes": ["catalog:read", "catalog:write"],
            },
            headers=headers,
        )
        assert created.status_code == 201
        body = created.json()
        assert body["user"]["roles"] == ["editor"]
        assert body["temporary_password"]
        user_id = body["user"]["id"]

        listed = await client.get("/api/v1/auth/users", headers=headers)
        assert listed.status_code == 200
        assert len(listed.json()["items"]) == 2

        detail = await client.get(f"/api/v1/auth/users/{user_id}", headers=headers)
        assert detail.status_code == 200

        updated = await client.patch(
            f"/api/v1/auth/users/{user_id}",
            json={"display_name": "Senior Editor", "scopes": ["catalog:read"]},
            headers=headers,
        )
        assert updated.status_code == 200
        assert updated.json()["display_name"] == "Senior Editor"

        reset = await client.post(
            f"/api/v1/auth/users/{user_id}/reset-password",
            headers=headers,
        )
        assert reset.status_code == 200
        assert reset.json()["temporary_password"] != body["temporary_password"]

        revoked = await client.post(
            f"/api/v1/auth/users/{user_id}/revoke-sessions",
            headers=headers,
        )
        assert revoked.status_code == 200
        assert revoked.json()["revoked_sessions"] == 0


@pytest.mark.asyncio
async def test_admin_router_is_optional_and_requires_admin_role(settings: AuthSettings) -> None:
    auth, client = await client_for(settings=settings, include_admin=False)
    async with client:
        signed_in = await login(client)
        missing = await client.get(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {signed_in.json()['access_token']}"},
        )
        assert missing.status_code == 404

    user = await auth.service.create_user(
        email="viewer@example.com",
        display_name="Viewer",
        roles=("viewer",),
    )
    app = FastAPI()
    auth.install(app, prefix="/auth2", include_admin=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as other:
        signed_in = await other.post(
            "/auth2/login",
            json={"email": user.user.email, "password": user.temporary_password},
            headers={"Origin": ORIGIN},
        )
        token = signed_in.json()["access_token"]
        denied = await other.get(
            "/auth2/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        # must-change is checked before role evaluation, keeping the more restrictive state.
        assert denied.status_code == 403
        assert denied.json()["code"] == "AUTH_PASSWORD_CHANGE_REQUIRED"


@pytest.mark.asyncio
async def test_openapi_contains_safe_auth_contracts(settings: AuthSettings) -> None:
    auth = EpokAuth(settings=settings, store=MemoryAuthStore())
    app = FastAPI()
    auth.install(app, prefix="/auth", include_admin=True)
    schema = app.openapi()
    assert {
        "/auth/login",
        "/auth/refresh",
        "/auth/logout",
        "/auth/me",
        "/auth/change-password",
        "/auth/users",
    } <= set(schema["paths"])
    session = schema["components"]["schemas"]["SessionResponse"]["properties"]
    assert "refresh_token" not in session
    assert "password_hash" not in str(schema)
    security = schema["paths"]["/auth/me"]["get"]["security"]
    assert security == [{"HTTPBearer": []}]


@pytest.mark.asyncio
async def test_secure_host_cookie_attributes_are_emitted(settings: AuthSettings) -> None:
    secure = settings.model_copy(
        update={
            "secure_cookies": True,
            "cookie_use_host_prefix": True,
            "trusted_origins": ("https://colors.example.com",),
        }
    )
    _, client = await client_for(settings=secure)
    async with client:
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
            headers={"Origin": "https://colors.example.com"},
        )
    for cookie in response.headers.get_list("set-cookie"):
        assert cookie.startswith("__Host-")
        assert "Secure" in cookie
        assert "HttpOnly" in cookie
        assert "Path=/" in cookie
        assert "Domain=" not in cookie
