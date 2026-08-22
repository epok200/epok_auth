from epok_auth.errores.catalogo import AuthErrorCode, Severidad, severidad_default


class AuthError(Exception):
    """Error de dominio de autenticación con aliases públicos compatibles."""

    __slots__ = ("_headers", "_status_code", "code", "detail", "severity")

    def __init__(
        self,
        code: AuthErrorCode,
        detail: str,
        status_code: int | None = None,
        headers: dict[str, str] | None = None,
        severity: Severidad | None = None,
    ) -> None:
        self.code = code
        self.detail = detail
        self.severity = severity if severity is not None else severidad_default(code)
        self._status_code = status_code
        self._headers = headers.copy() if headers is not None else None
        super().__init__(detail)

    def __reduce__(self) -> tuple[object, tuple[object, ...]]:
        return (
            type(self),
            (
                self.code,
                self.detail,
                self._status_code,
                self.headers_override,
                self.severity,
            ),
        )

    @property
    def codigo(self) -> AuthErrorCode:
        return self.code

    @property
    def detalle(self) -> str:
        return self.detail

    @property
    def severidad(self) -> Severidad:
        return self.severity

    @property
    def status_code_override(self) -> int | None:
        return self._status_code

    @property
    def headers_override(self) -> dict[str, str] | None:
        return self._headers.copy() if self._headers is not None else None

    @property
    def status_code(self) -> int:
        from epok_auth.errores.http import status_http

        return status_http(self)

    @property
    def headers(self) -> dict[str, str] | None:
        from epok_auth.errores.http import headers_http

        return headers_http(self)


AppError = AuthError


def invalid_credentials() -> AuthError:
    return AuthError(
        AuthErrorCode.INVALID_CREDENTIALS,
        "The email or password is not valid.",
    )


def invalid_session() -> AuthError:
    return AuthError(
        AuthErrorCode.INVALID_TOKEN,
        "The session is not valid.",
    )


def invalid_csrf() -> AuthError:
    return AuthError(
        AuthErrorCode.INVALID_CSRF,
        "CSRF protection failed.",
    )


def forbidden(detail: str = "You are not allowed to perform this operation.") -> AuthError:
    return AuthError(AuthErrorCode.FORBIDDEN, detail)
