import httpx
import pytest
from fastapi import FastAPI

from epok_auth import EpokAuth
from epok_auth.testing import MemoryAuthStore
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD
from tests.passkeys.virtual_authenticator import VirtualAuthenticator, decode_base64url

ORIGIN = "http://localhost:3000"
RP_ID = "localhost"
PREFIX = "/api/v1/auth"


async def passkey_client(settings):
    configured = settings.model_copy(
        update={
            "passkey_rp_id": RP_ID,
            "passkey_rp_name": "EPOK Tests",
        }
    )
    auth = EpokAuth(settings=configured, store=MemoryAuthStore())
    await auth.service.create_admin(
        email=ADMIN_EMAIL,
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    app = FastAPI()
    auth.install(app, prefix=PREFIX, include_passkeys=True)
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://testserver")
    return auth, app, client, VirtualAuthenticator()


async def password_login(client: httpx.AsyncClient) -> str:
    response = await client.post(
        f"{PREFIX}/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


async def register(
    client: httpx.AsyncClient,
    authenticator: VirtualAuthenticator,
    access_token: str,
) -> dict[str, object]:
    headers = {"Authorization": f"Bearer {access_token}", "Origin": ORIGIN}
    options = await client.post(f"{PREFIX}/passkeys/registration/options", headers=headers)
    assert options.status_code == 200
    assert options.headers["cache-control"] == "no-store"
    body = options.json()
    public_key = body["publicKey"]
    response = authenticator.registration_response(
        challenge=decode_base64url(public_key["challenge"]),
        rp_id=RP_ID,
        origin=ORIGIN,
    )
    registered = await client.post(
        f"{PREFIX}/passkeys/registration/verify",
        json={
            "ceremony_id": body["ceremony_id"],
            "name": "MacBook Touch ID",
            "credential": response,
        },
        headers=headers,
    )
    assert registered.status_code == 201
    assert registered.headers["cache-control"] == "no-store"
    return registered.json()


@pytest.mark.asyncio
@pytest.mark.security
async def test_complete_passkey_http_flow(settings) -> None:
    auth, _, client, authenticator = await passkey_client(settings)
    async with client:
        password_token = await password_login(client)
        user_id = (await auth.service.list_users())[0].id
        registered = await register(client, authenticator, password_token)
        bearer = {"Authorization": f"Bearer {password_token}"}
        listed = await client.get(f"{PREFIX}/passkeys", headers=bearer)

        options = await client.post(
            f"{PREFIX}/passkeys/authentication/options",
            headers={"Origin": ORIGIN},
        )
        body = options.json()
        response = authenticator.authentication_response(
            challenge=decode_base64url(body["publicKey"]["challenge"]),
            rp_id=RP_ID,
            origin=ORIGIN,
            user_id=user_id,
            sign_count=1,
        )
        authenticated = await client.post(
            f"{PREFIX}/passkeys/authentication/verify",
            json={"ceremony_id": body["ceremony_id"], "credential": response},
            headers={"Origin": ORIGIN},
        )

        assert registered["name"] == "MacBook Touch ID"
        assert registered["backed_up"] is True
        assert listed.status_code == 200
        assert listed.headers["cache-control"] == "no-store"
        assert listed.json()["items"] == [registered]
        assert options.status_code == 200
        assert options.headers["cache-control"] == "no-store"
        assert authenticated.status_code == 200
        assert authenticated.json()["user"]["email"] == ADMIN_EMAIL
        assert authenticated.headers["cache-control"] == "no-store"
        assert len(authenticated.headers.get_list("set-cookie")) == 2

        passkey_token = authenticated.json()["access_token"]
        me = await client.get(
            f"{PREFIX}/me",
            headers={"Authorization": f"Bearer {passkey_token}"},
        )
        revoked = await client.delete(
            f"{PREFIX}/passkeys/{registered['id']}",
            headers={"Authorization": f"Bearer {passkey_token}", "Origin": ORIGIN},
        )
        still_authenticated = await client.get(
            f"{PREFIX}/me",
            headers={"Authorization": f"Bearer {passkey_token}"},
        )
        empty = await client.get(
            f"{PREFIX}/passkeys",
            headers={"Authorization": f"Bearer {passkey_token}"},
        )

        assert me.status_code == 200
        assert revoked.status_code == 204
        assert revoked.headers["cache-control"] == "no-store"
        assert still_authenticated.status_code == 200
        assert empty.json() == {"items": []}


@pytest.mark.asyncio
async def test_passkey_routes_are_opt_in_and_documented_in_openapi(settings) -> None:
    missing_rp = EpokAuth(settings=settings, store=MemoryAuthStore())
    unmodified = FastAPI()
    with pytest.raises(ValueError, match="passkey_rp_id"):
        missing_rp.install(unmodified, prefix=PREFIX, include_passkeys=True)
    assert unmodified.openapi()["paths"] == {}

    configured = settings.model_copy(update={"passkey_rp_id": RP_ID})
    auth = EpokAuth(settings=configured, store=MemoryAuthStore())
    disabled = FastAPI()
    auth.install(disabled, prefix=PREFIX)
    enabled = FastAPI()
    auth.install(enabled, prefix=PREFIX, include_passkeys=True)

    assert not any("passkeys" in path for path in disabled.openapi()["paths"])
    assert {
        f"{PREFIX}/passkeys/registration/options",
        f"{PREFIX}/passkeys/registration/verify",
        f"{PREFIX}/passkeys/authentication/options",
        f"{PREFIX}/passkeys/authentication/verify",
        f"{PREFIX}/passkeys",
        f"{PREFIX}/passkeys/{{passkey_id}}",
    } <= set(enabled.openapi()["paths"])
    schemas = str(enabled.openapi()["components"]["schemas"])
    assert "PasskeyOptionsResponse" in schemas
    assert "public_key" not in schemas


@pytest.mark.asyncio
async def test_passkey_http_rejects_untrusted_origin_and_malformed_payload(settings) -> None:
    _, _, client, _ = await passkey_client(settings)
    async with client:
        token = await password_login(client)
        headers = {"Authorization": f"Bearer {token}"}
        untrusted = await client.post(
            f"{PREFIX}/passkeys/registration/options",
            headers={**headers, "Origin": "https://evil.example"},
        )
        missing_origin = await client.post(f"{PREFIX}/passkeys/authentication/options")
        secret = "private-value-" * 500
        malformed = await client.post(
            f"{PREFIX}/passkeys/registration/verify",
            json={"ceremony_id": "invalid", "name": secret, "credential": {}},
            headers={**headers, "Origin": ORIGIN},
        )

    assert untrusted.status_code == 403
    assert untrusted.json()["code"] == "AUTH_ORIGIN_INVALID"
    assert missing_origin.status_code == 403
    assert missing_origin.json()["code"] == "AUTH_ORIGIN_INVALID"
    assert malformed.status_code == 422
    assert malformed.json()["code"] == "AUTH_INPUT_INVALID"
    assert secret not in malformed.text
