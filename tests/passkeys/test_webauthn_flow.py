from uuid import uuid4

import pytest

from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.passkeys.service import PasskeyService
from epok_auth.passkeys.webauthn import WebAuthnAdapter
from epok_auth.service import AuthService
from epok_auth.testing import MemoryAuthStore
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, MutableClock
from tests.passkeys.virtual_authenticator import VirtualAuthenticator, decode_base64url

ORIGIN = "http://localhost:3000"
RP_ID = "localhost"


async def real_flow(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
):
    configured = settings.model_copy(update={"passkey_rp_id": RP_ID})
    auth = AuthService(store=store, settings=configured, clock=clock)
    await auth.create_admin(email=ADMIN_EMAIL, display_name="Admin", password=ADMIN_PASSWORD)
    password_session = await auth.login(ADMIN_EMAIL, ADMIN_PASSWORD)
    passkeys = PasskeyService(
        store=store,
        settings=configured,
        signer=auth.signer,
        adapter=WebAuthnAdapter(
            rp_id=RP_ID,
            rp_name="EPOK Tests",
            timeout_ms=60_000,
        ),
        clock=clock,
    )
    return auth, passkeys, password_session, VirtualAuthenticator()


@pytest.mark.asyncio
@pytest.mark.security
async def test_real_webauthn_registration_and_authentication_round_trip(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    auth, passkeys, password_session, authenticator = await real_flow(store, settings, clock)
    registration = await passkeys.begin_registration(password_session.principal, ORIGIN)
    registration_challenge = decode_base64url(registration.public_key["challenge"])
    registration_response = authenticator.registration_response(
        challenge=registration_challenge,
        rp_id=RP_ID,
        origin=ORIGIN,
    )
    credential = await passkeys.finish_registration(
        password_session.principal,
        registration.ceremony_id,
        "Virtual platform passkey",
        registration_response,
        ORIGIN,
    )

    authentication = await passkeys.begin_authentication(ORIGIN)
    authentication_challenge = decode_base64url(authentication.public_key["challenge"])
    authentication_response = authenticator.authentication_response(
        challenge=authentication_challenge,
        rp_id=RP_ID,
        origin=ORIGIN,
        user_id=password_session.principal.user_id,
        sign_count=1,
    )
    passkey_session = await passkeys.finish_authentication(
        authentication.ceremony_id,
        authentication_response,
        ORIGIN,
    )

    assert credential.credential_id == authenticator.credential_id
    assert credential.device_type == "multi_device"
    assert credential.backed_up is True
    assert set(credential.transports) == {"hybrid", "internal"}
    assert (await auth.authenticate(passkey_session.access_token)).user_id == credential.user_id
    assert store.passkeys[credential.id].sign_count == 1


@pytest.mark.asyncio
@pytest.mark.security
async def test_real_webauthn_rejects_wrong_challenge_and_consumes_ceremony(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    _, passkeys, password_session, authenticator = await real_flow(store, settings, clock)
    registration = await passkeys.begin_registration(password_session.principal, ORIGIN)
    response = authenticator.registration_response(
        challenge=b"wrong-challenge-with-enough-entropy",
        rp_id=RP_ID,
        origin=ORIGIN,
    )

    with pytest.raises(AuthError) as invalid:
        await passkeys.finish_registration(
            password_session.principal,
            registration.ceremony_id,
            "Virtual passkey",
            response,
            ORIGIN,
        )
    with pytest.raises(AuthError) as replay:
        await passkeys.finish_registration(
            password_session.principal,
            registration.ceremony_id,
            "Virtual passkey",
            response,
            ORIGIN,
        )

    assert invalid.value.code is AuthErrorCode.PASSKEY_REGISTRATION_INVALID
    assert replay.value.code is AuthErrorCode.PASSKEY_CHALLENGE_INVALID


@pytest.mark.asyncio
@pytest.mark.security
@pytest.mark.parametrize(
    "client_flags",
    [
        {"cross_origin": True},
        {"cross_origin": 1},
        {"top_origin": "https://embedded.example"},
    ],
)
async def test_real_webauthn_rejects_cross_origin_client_data(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
    client_flags: dict[str, object],
) -> None:
    _, passkeys, password_session, authenticator = await real_flow(store, settings, clock)
    registration = await passkeys.begin_registration(password_session.principal, ORIGIN)
    challenge = decode_base64url(registration.public_key["challenge"])
    response = authenticator.registration_response(
        challenge=challenge,
        rp_id=RP_ID,
        origin=ORIGIN,
        **client_flags,
    )

    with pytest.raises(AuthError) as captured:
        await passkeys.finish_registration(
            password_session.principal,
            registration.ceremony_id,
            "Virtual passkey",
            response,
            ORIGIN,
        )

    assert captured.value.code is AuthErrorCode.PASSKEY_REGISTRATION_INVALID


@pytest.mark.asyncio
@pytest.mark.security
@pytest.mark.parametrize(
    "response_values",
    [
        {"origin": "https://wrong.example"},
        {"rp_id": "wrong.example"},
        {"user_present": False},
        {"user_verified": False},
        {"backup_eligible": False, "backed_up": True},
    ],
)
async def test_real_webauthn_rejects_invalid_registration_proofs(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
    response_values: dict[str, object],
) -> None:
    _, passkeys, password_session, authenticator = await real_flow(store, settings, clock)
    registration = await passkeys.begin_registration(password_session.principal, ORIGIN)
    values: dict[str, object] = {
        "challenge": decode_base64url(registration.public_key["challenge"]),
        "rp_id": RP_ID,
        "origin": ORIGIN,
    }
    values.update(response_values)
    response = authenticator.registration_response(**values)

    with pytest.raises(AuthError) as captured:
        await passkeys.finish_registration(
            password_session.principal,
            registration.ceremony_id,
            "Invalid virtual passkey",
            response,
            ORIGIN,
        )

    assert captured.value.code is AuthErrorCode.PASSKEY_REGISTRATION_INVALID


@pytest.mark.asyncio
@pytest.mark.security
@pytest.mark.parametrize(
    "response_values",
    [
        {"origin": "https://wrong.example"},
        {"rp_id": "wrong.example"},
        {"user_present": False},
        {"user_verified": False},
        {"backup_eligible": False, "backed_up": True},
        {"valid_signature": False},
    ],
)
async def test_real_webauthn_rejects_invalid_authentication_proofs(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
    response_values: dict[str, object],
) -> None:
    _, passkeys, password_session, authenticator = await real_flow(store, settings, clock)
    registration = await passkeys.begin_registration(password_session.principal, ORIGIN)
    registration_response = authenticator.registration_response(
        challenge=decode_base64url(registration.public_key["challenge"]),
        rp_id=RP_ID,
        origin=ORIGIN,
    )
    await passkeys.finish_registration(
        password_session.principal,
        registration.ceremony_id,
        "Virtual passkey",
        registration_response,
        ORIGIN,
    )
    authentication = await passkeys.begin_authentication(ORIGIN)
    values: dict[str, object] = {
        "challenge": decode_base64url(authentication.public_key["challenge"]),
        "rp_id": RP_ID,
        "origin": ORIGIN,
        "user_id": password_session.principal.user_id,
        "sign_count": 1,
    }
    values.update(response_values)
    response = authenticator.authentication_response(**values)

    with pytest.raises(AuthError) as captured:
        await passkeys.finish_authentication(
            authentication.ceremony_id,
            response,
            ORIGIN,
        )

    assert captured.value.code is AuthErrorCode.PASSKEY_AUTHENTICATION_INVALID


@pytest.mark.asyncio
@pytest.mark.security
async def test_real_webauthn_rejects_wrong_user_handle_and_counter_replay(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    _, passkeys, password_session, authenticator = await real_flow(store, settings, clock)
    registration = await passkeys.begin_registration(password_session.principal, ORIGIN)
    registration_response = authenticator.registration_response(
        challenge=decode_base64url(registration.public_key["challenge"]),
        rp_id=RP_ID,
        origin=ORIGIN,
    )
    credential = await passkeys.finish_registration(
        password_session.principal,
        registration.ceremony_id,
        "Virtual passkey",
        registration_response,
        ORIGIN,
    )

    wrong_handle = await passkeys.begin_authentication(ORIGIN)
    wrong_handle_response = authenticator.authentication_response(
        challenge=decode_base64url(wrong_handle.public_key["challenge"]),
        rp_id=RP_ID,
        origin=ORIGIN,
        user_id=password_session.principal.user_id,
        user_handle=uuid4().bytes,
        sign_count=1,
    )
    with pytest.raises(AuthError) as handle_error:
        await passkeys.finish_authentication(
            wrong_handle.ceremony_id,
            wrong_handle_response,
            ORIGIN,
        )

    first = await passkeys.begin_authentication(ORIGIN)
    first_response = authenticator.authentication_response(
        challenge=decode_base64url(first.public_key["challenge"]),
        rp_id=RP_ID,
        origin=ORIGIN,
        user_id=password_session.principal.user_id,
        sign_count=1,
    )
    await passkeys.finish_authentication(first.ceremony_id, first_response, ORIGIN)

    replay = await passkeys.begin_authentication(ORIGIN)
    replay_response = authenticator.authentication_response(
        challenge=decode_base64url(replay.public_key["challenge"]),
        rp_id=RP_ID,
        origin=ORIGIN,
        user_id=password_session.principal.user_id,
        sign_count=1,
    )
    with pytest.raises(AuthError) as counter_error:
        await passkeys.finish_authentication(replay.ceremony_id, replay_response, ORIGIN)

    assert credential.id in store.passkeys
    assert handle_error.value.code is AuthErrorCode.PASSKEY_AUTHENTICATION_INVALID
    assert counter_error.value.code is AuthErrorCode.PASSKEY_AUTHENTICATION_INVALID
