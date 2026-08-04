from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

import jwt

from epok_auth.errors import invalid_session
from epok_auth.models import AccessClaims, Principal

Clock = Callable[[], datetime]
_JTI = re.compile(r"[0-9a-f]{32}")


def utc_now() -> datetime:
    return datetime.now(UTC)


class AccessTokenSigner(Protocol):
    def issue(self, principal: Principal, *, now: datetime) -> tuple[str, datetime]: ...
    def verify(self, token: str) -> AccessClaims: ...


@dataclass(frozen=True, slots=True)
class HMACJWTSigner:
    secret: str = field(repr=False)
    issuer: str
    audience: str
    access_ttl_seconds: int = 15 * 60
    algorithm: str = "HS256"
    leeway_seconds: int = 30
    max_token_chars: int = 8192
    clock: Clock = field(default=utc_now, repr=False, compare=False)

    def issue(self, principal: Principal, *, now: datetime) -> tuple[str, datetime]:
        now = _as_utc(now)
        expires_at = now + timedelta(seconds=self.access_ttl_seconds)
        payload = {
            "sub": str(principal.user_id),
            "sid": str(principal.session_id),
            "fid": str(principal.family_id),
            "type": "access",
            "jti": uuid4().hex,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "auth_time": int(principal.authenticated_at.timestamp()),
            "iss": self.issuer,
            "aud": self.audience,
        }
        return jwt.encode(payload, self.secret, algorithm=self.algorithm), expires_at

    def verify(self, token: str) -> AccessClaims:
        if not token or len(token) > self.max_token_chars:
            raise invalid_session()
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=self.audience,
                options={
                    "require": [
                        "sub",
                        "sid",
                        "fid",
                        "type",
                        "jti",
                        "iat",
                        "nbf",
                        "exp",
                        "auth_time",
                        "iss",
                        "aud",
                    ],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
            if payload["type"] != "access":
                raise jwt.InvalidTokenError("unexpected token type")
            token_id = str(payload["jti"])
            if _JTI.fullmatch(token_id) is None:
                raise jwt.InvalidTokenError("invalid token identifier")
            issued_at = datetime.fromtimestamp(_numeric_date(payload, "iat"), tz=UTC)
            not_before = datetime.fromtimestamp(_numeric_date(payload, "nbf"), tz=UTC)
            expires_at = datetime.fromtimestamp(_numeric_date(payload, "exp"), tz=UTC)
            authenticated_at = datetime.fromtimestamp(_numeric_date(payload, "auth_time"), tz=UTC)
            now = _as_utc(self.clock())
            leeway = timedelta(seconds=self.leeway_seconds)
            if issued_at > now + leeway or not_before > now + leeway:
                raise jwt.InvalidTokenError("token is not active")
            if abs((not_before - issued_at).total_seconds()) > self.leeway_seconds:
                raise jwt.InvalidTokenError("not-before time is inconsistent")
            if authenticated_at > issued_at + leeway:
                raise jwt.InvalidTokenError("authentication time is invalid")
            if expires_at - issued_at > timedelta(seconds=self.access_ttl_seconds) + leeway:
                raise jwt.InvalidTokenError("token lifetime is invalid")
            if expires_at <= now - leeway or expires_at <= issued_at:
                raise jwt.InvalidTokenError("token has expired")
            return AccessClaims(
                user_id=UUID(str(payload["sub"])),
                session_id=UUID(str(payload["sid"])),
                family_id=UUID(str(payload["fid"])),
                issued_at=issued_at,
                expires_at=expires_at,
                token_id=token_id,
                authenticated_at=authenticated_at,
            )
        except (jwt.PyJWTError, KeyError, TypeError, ValueError, OverflowError) as error:
            raise invalid_session() from error


def create_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def create_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def secure_token_equals(left: str, right: str) -> bool:
    return secrets.compare_digest(left, right)


def _numeric_date(payload: dict[str, object], name: str) -> int:
    value = payload[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise jwt.InvalidTokenError(f"{name} must be a numeric date")
    numeric = int(value)
    if numeric != value:
        raise jwt.InvalidTokenError(f"{name} must contain whole seconds")
    return numeric


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(UTC)
