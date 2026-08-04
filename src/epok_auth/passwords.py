from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Protocol

from epok_auth.errors import AuthError, AuthErrorCode


class PasswordHash(Protocol):
    def hash(self, password: str) -> str: ...
    def verify_and_update(self, password: str, encoded_hash: str) -> tuple[bool, str | None]: ...


def _recommended_hash() -> PasswordHash:
    try:
        from pwdlib import PasswordHash as PwdlibPasswordHash

        return PwdlibPasswordHash.recommended()
    except ImportError:  # pragma: no cover - fallback for restricted source checkouts
        return _Argon2Fallback()


class _Argon2Fallback:
    def __init__(self) -> None:
        from argon2 import PasswordHasher

        self._hasher = PasswordHasher()

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify_and_update(self, password: str, encoded_hash: str) -> tuple[bool, str | None]:
        from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

        try:
            valid = self._hasher.verify(encoded_hash, password)
        except (InvalidHashError, VerificationError, VerifyMismatchError):
            return False, None
        updated = (
            self.hash(password) if valid and self._hasher.check_needs_rehash(encoded_hash) else None
        )
        return bool(valid), updated


class PasswordRule(Protocol):
    def validate(self, password: str) -> None: ...


@dataclass(frozen=True, slots=True)
class PasswordLengthRule:
    minimum: int = 15
    maximum: int = 128

    def validate(self, password: str) -> None:
        if not self.minimum <= len(password) <= self.maximum:
            raise AuthError(
                AuthErrorCode.PASSWORD_INVALID,
                f"Password must contain between {self.minimum} and {self.maximum} characters.",
                status_code=422,
            )


@dataclass(frozen=True, slots=True)
class CommonPasswordRule:
    denied: frozenset[str] = frozenset(
        {
            "123456789012345",
            "correct horse battery staple",
            "passwordpassword",
            "qwertyuiopasdfgh",
        }
    )

    def validate(self, password: str) -> None:
        candidate = password.casefold()
        if any(hmac.compare_digest(candidate, denied) for denied in self.denied):
            raise AuthError(
                AuthErrorCode.PASSWORD_INVALID,
                "Password is too common or has been explicitly denied.",
                status_code=422,
            )


@dataclass(frozen=True, slots=True)
class PasswordVerification:
    valid: bool
    updated_hash: str | None = None


class PasswordManager:
    def __init__(
        self,
        *,
        rules: tuple[PasswordRule, ...],
        password_hash: PasswordHash | None = None,
    ) -> None:
        self._rules = rules
        self._password_hash = password_hash or _recommended_hash()
        self._dummy_hash = self._password_hash.hash(
            "epok-auth-dummy-password-never-used-for-authentication"
        )

    @classmethod
    def recommended(
        cls,
        *,
        minimum: int = 15,
        maximum: int = 128,
        password_hash: PasswordHash | None = None,
        additional_rules: tuple[PasswordRule, ...] = (),
    ) -> PasswordManager:
        return cls(
            rules=(PasswordLengthRule(minimum, maximum), CommonPasswordRule(), *additional_rules),
            password_hash=password_hash,
        )

    def validate(self, password: str) -> None:
        for rule in self._rules:
            rule.validate(password)

    def hash(self, password: str) -> str:
        self.validate(password)
        return self._password_hash.hash(password)

    def verify(self, password: str, encoded_hash: str) -> PasswordVerification:
        valid, updated = self._password_hash.verify_and_update(password, encoded_hash)
        return PasswordVerification(valid=valid, updated_hash=updated if valid else None)

    def verify_for_login(self, password: str, encoded_hash: str | None) -> PasswordVerification:
        # Bound attacker-controlled work before Argon2 while still executing a dummy verification.
        if len(password) > 4096:
            self._password_hash.verify_and_update(
                "invalid-password-too-long",
                encoded_hash or self._dummy_hash,
            )
            return PasswordVerification(valid=False)
        candidate_hash = encoded_hash or self._dummy_hash
        result = self.verify(password, candidate_hash)
        return result if encoded_hash is not None else PasswordVerification(valid=False)
