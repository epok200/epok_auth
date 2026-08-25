from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import jwt
import pytest

from epok_auth.errors import AuthError, AuthErrorCode
from epok_auth.models import Principal
from epok_auth.tokens import (
    HMACJWTSigner,
    clock_now,
    create_csrf_token,
    create_refresh_token,
    secure_token_equals,
    token_hash,
)

SECRET = "token-test-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
NOW = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)


def principal() -> Principal:
    return Principal(
        user_id=uuid4(),
        session_id=uuid4(),
        family_id=uuid4(),
        email="user@example.com",
        display_name="User",
        roles=("user",),
        scopes=("catalog:read",),
        must_change_password=False,
        authenticated_at=NOW - timedelta(minutes=1),
    )


def signer(now: datetime = NOW) -> HMACJWTSigner:
    return HMACJWTSigner(
        secret=SECRET,
        issuer="tests",
        audience="tests-api",
        access_ttl_seconds=300,
        leeway_seconds=5,
        clock=lambda: now,
    )


def test_issue_and_verify_strict_access_token() -> None:
    subject = principal()
    token, expires_at = signer().issue(subject, now=NOW)
    claims = signer().verify(token)
    assert claims.user_id == subject.user_id
    assert claims.session_id == subject.session_id
    assert claims.family_id == subject.family_id
    assert claims.authenticated_at == subject.authenticated_at
    assert expires_at == NOW + timedelta(seconds=300)
    payload = jwt.decode(
        token, SECRET, algorithms=["HS256"], options={"verify_aud": False, "verify_exp": False}
    )
    assert payload["type"] == "access"
    assert payload["iss"] == "tests"
    assert payload["aud"] == "tests-api"
    assert len(payload["jti"]) == 32


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update(type="refresh"),
        lambda payload: payload.pop("sid"),
        lambda payload: payload.update(jti="not-a-jti"),
        lambda payload: payload.update(aud="other-api"),
        lambda payload: payload.update(iss="other-issuer"),
        lambda payload: payload.update(iat=True),
        lambda payload: payload.update(exp=payload["iat"]),
        lambda payload: payload.update(exp=payload["iat"] + 9999),
        lambda payload: payload.update(auth_time=payload["iat"] + 100),
        lambda payload: payload.update(nbf=payload["iat"] + 100),
        lambda payload: payload.update(nbf=payload["iat"] - 100),
        lambda payload: payload.update(iat=payload["iat"] + 0.5),
    ],
)
def test_rejects_malformed_or_policy_violating_claims(mutate: object) -> None:
    subject = principal()
    token, _ = signer().issue(subject, now=NOW)
    payload = jwt.decode(
        token,
        SECRET,
        algorithms=["HS256"],
        options={"verify_signature": False},
    )
    mutate(payload)  # type: ignore[operator]
    malicious = jwt.encode(payload, SECRET, algorithm="HS256")
    with pytest.raises(AuthError) as captured:
        signer().verify(malicious)
    assert captured.value.code is AuthErrorCode.INVALID_TOKEN


def test_rejects_expired_future_unsigned_and_oversized_tokens() -> None:
    subject = principal()
    token, _ = signer().issue(subject, now=NOW)
    with pytest.raises(AuthError):
        signer(NOW + timedelta(minutes=10)).verify(token)
    with pytest.raises(AuthError):
        signer(NOW - timedelta(minutes=10)).verify(token)
    unsigned = jwt.encode(
        {"sub": "x"},
        key="",
        algorithm="none",
    )
    with pytest.raises(AuthError):
        signer().verify(unsigned)
    with pytest.raises(AuthError):
        signer().verify("x" * 9000)
    with pytest.raises(AuthError):
        signer().verify("")


def test_rejects_wrong_signature() -> None:
    subject = principal()
    token, _ = signer().issue(subject, now=NOW)
    wrong = replace(signer(), secret="different-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    with pytest.raises(AuthError):
        wrong.verify(token)


def test_opaque_tokens_have_entropy_and_hashes_are_stable() -> None:
    refresh_one = create_refresh_token()
    refresh_two = create_refresh_token()
    csrf = create_csrf_token()
    assert refresh_one != refresh_two
    assert len(refresh_one) >= 64
    assert len(csrf) >= 40
    assert len(token_hash(refresh_one)) == 64
    assert token_hash(refresh_one) == token_hash(refresh_one)
    assert secure_token_equals(csrf, csrf)
    assert not secure_token_equals(csrf, refresh_one)


def test_issue_rejects_naive_datetime() -> None:
    subject = principal()
    with pytest.raises(ValueError, match="timezone-aware"):
        signer().issue(subject, now=datetime(2026, 8, 4, 12, 0))


def test_clock_now_normalizes_to_utc() -> None:
    local_time = datetime(2026, 8, 4, 6, 0, tzinfo=timezone(timedelta(hours=-6)))

    assert clock_now(lambda: local_time) == NOW


def test_clock_now_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="clock must return a timezone-aware datetime"):
        clock_now(lambda: datetime(2026, 8, 4, 12, 0))
