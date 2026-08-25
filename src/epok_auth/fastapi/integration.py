# pyright: reportUnusedFunction=false
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Annotated, Any, Self, cast

from fastapi import APIRouter, Depends, FastAPI
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from epok_auth.config import AuthSettings, Environment
from epok_auth.email_links.dispatcher import EmailLinkDispatcher
from epok_auth.email_links.mailer import EmailLinkMailer
from epok_auth.email_links.service import EmailLinkService
from epok_auth.email_links.smtp import EmailLinkSender, SmtpEmailSender, SmtpSettings
from epok_auth.email_links.store import EmailLinkStore
from epok_auth.errores import AuthError, AuthErrorCode, invalid_session
from epok_auth.fastapi._installation import (
    AuthInstallState,
    install_exception_handlers,
    install_state,
)
from epok_auth.fastapi._local import create_admin_router, create_auth_router
from epok_auth.fastapi.email_links import (
    create_email_link_admin_router,
    create_email_link_router,
)
from epok_auth.fastapi.google import create_google_admin_router, create_google_router
from epok_auth.fastapi.passkeys import create_passkey_router
from epok_auth.fastapi.transport import AuthHttpTransport
from epok_auth.google.service import GoogleLoginService
from epok_auth.google.store import GoogleStore
from epok_auth.models import Principal
from epok_auth.passkeys.service import PasskeyService
from epok_auth.passkeys.store import PasskeyStore
from epok_auth.service import AuthService
from epok_auth.store import AuthStore

PrincipalDependency = Principal
SafeAuthRoute = APIRoute
_bearer = HTTPBearer(auto_error=False)


class EpokAuth:
    """FastAPI-first facade over the authentication service."""

    def __init__(
        self,
        *,
        settings: AuthSettings,
        store: AuthStore,
        service: AuthService | None = None,
        passkeys: PasskeyService | None = None,
        google: GoogleLoginService | None = None,
        google_store: GoogleStore | None = None,
        email_link_service: EmailLinkService | None = None,
        email_link_sender: EmailLinkSender | None = None,
        email_link_store: EmailLinkStore | None = None,
        email_link_dispatcher: EmailLinkDispatcher | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.service = service or AuthService(store=store, settings=settings)
        self.passkeys = passkeys
        self.google = google
        self.google_store = google_store
        self.email_link_service = email_link_service
        self.email_link_sender = email_link_sender
        self.email_link_store = email_link_store
        self.email_link_dispatcher = email_link_dispatcher
        self._email_link_mailer: EmailLinkMailer | None = None
        self._http = AuthHttpTransport(settings)
        self._resources = AsyncExitStack()
        self._app: FastAPI | None = None
        self._owns_resources = google_store is not None and google is None

    @classmethod
    def postgres(
        cls,
        *,
        settings: AuthSettings,
        pool_size: int = 5,
        max_overflow: int = 10,
        pool_timeout: float = 5.0,
        email_link_sender: EmailLinkSender | None = None,
        email_link_dispatcher: EmailLinkDispatcher | None = None,
    ) -> Self:
        if settings.database_url is None:
            raise ValueError("database_url is required for the PostgreSQL adapter")
        from epok_auth.postgres import PostgresAuthStore

        store = PostgresAuthStore.from_url(
            settings.database_url.get_secret_value(),
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
        )
        auth = cls(
            settings=settings,
            store=store,
            google_store=store,
            email_link_sender=email_link_sender,
            email_link_dispatcher=email_link_dispatcher,
        )
        auth._resources.push_async_callback(store.aclose)
        auth._owns_resources = True
        return auth

    @asynccontextmanager
    async def lifespan(self, app: FastAPI) -> AsyncGenerator[None, None]:
        try:
            yield
        finally:
            state = getattr(app.state, "_epok_auth_install_state", None)
            facades = list(state.facades) if isinstance(state, AuthInstallState) else []
            if self not in facades:
                facades.append(self)
            cleanup = AsyncExitStack()
            for facade in facades:
                cleanup.push_async_callback(facade.aclose)
            await cleanup.aclose()

    async def aclose(self) -> None:
        """Close resources created internally by this facade."""
        await self._resources.aclose()

    def install(
        self,
        app: FastAPI,
        *,
        prefix: str = "/auth",
        include_admin: bool = False,
        include_passkeys: bool = False,
        include_google: bool = False,
        include_email_links: bool = False,
        admin_prefix: str = "/users",
    ) -> None:
        normalized_prefix = "/" + prefix.strip("/")
        routers = [self.router(prefix=normalized_prefix)]
        if include_admin:
            routers.append(
                self.admin_router(prefix=normalized_prefix + "/" + admin_prefix.strip("/"))
            )
        if include_passkeys:
            routers.append(self.passkey_router(prefix=normalized_prefix + "/passkeys"))
        if include_google:
            routers.append(self.google_router(prefix=normalized_prefix + "/google"))
            if include_admin:
                routers.append(
                    self.google_admin_router(
                        prefix=normalized_prefix + "/" + admin_prefix.strip("/")
                    )
                )
        if include_email_links:
            routers.append(self.email_link_router(prefix=normalized_prefix + "/email-links"))
            if include_admin:
                routers.append(
                    self.email_link_admin_router(
                        prefix=normalized_prefix + "/" + admin_prefix.strip("/")
                    )
                )

        auth_install_state = install_state(app)
        if self._owns_resources and self._app is not None and self._app is not app:
            raise ValueError("an EpokAuth resource owner cannot be installed in multiple apps")
        auth_install_state.register(normalized_prefix, self)
        self._app = app
        for router in routers:
            app.include_router(router)
        install_exception_handlers(app)

    def router(self, *, prefix: str = "/auth") -> APIRouter:
        return create_auth_router(
            self.service,
            self._http,
            self.current_user,
            prefix=prefix,
        )

    def admin_router(self, *, prefix: str = "/auth/users") -> APIRouter:
        return create_admin_router(
            self.service,
            self._http,
            self.require_roles(self.settings.admin_role),
            prefix=prefix,
        )

    def passkey_router(self, *, prefix: str = "/auth/passkeys") -> APIRouter:
        return create_passkey_router(
            service=self._passkey_service(),
            principal_dependency=self.authenticated,
            set_session_cookies=self._http.set_session_cookies,
            request_context=self._http.request_context,
            disable_cache=self._http.disable_cache,
            prefix=prefix,
        )

    def google_router(self, *, prefix: str = "/auth/google") -> APIRouter:
        return create_google_router(
            service=self._google_service(),
            principal_dependency=self.authenticated,
            set_session_cookies=self._http.set_session_cookies,
            request_context=self._http.request_context,
            disable_cache=self._http.disable_cache,
            prefix=prefix,
        )

    def google_admin_router(self, *, prefix: str = "/auth/users") -> APIRouter:
        return create_google_admin_router(
            service=self._google_service(),
            admin_dependency=self.require_roles(self.settings.admin_role),
            request_context=self._http.request_context,
            disable_cache=self._http.disable_cache,
            prefix=prefix,
        )

    def email_link_router(self, *, prefix: str = "/auth/email-links") -> APIRouter:
        dispatcher = self._email_dispatcher()
        return create_email_link_router(
            service=self._email_links(),
            mailer=None if dispatcher is not None else self._email_mailer(),
            transport=self._http,
            validate_origin=self.service.validate_origin,
            prefix=prefix,
            dispatcher=dispatcher,
        )

    def email_link_admin_router(self, *, prefix: str = "/auth/users") -> APIRouter:
        dispatcher = self._email_dispatcher()
        return create_email_link_admin_router(
            service=self._email_links(),
            mailer=None if dispatcher is not None else self._email_mailer(),
            transport=self._http,
            validate_origin=self.service.validate_origin,
            admin_dependency=self.require_roles(self.settings.admin_role),
            prefix=prefix,
            dispatcher=dispatcher,
        )

    async def current_user(
        self,
        credentials: Annotated[
            HTTPAuthorizationCredentials | None,
            Depends(_bearer),
        ],
    ) -> Principal:
        return await self._principal_from_credentials(credentials)

    async def authenticated(
        self,
        credentials: Annotated[
            HTTPAuthorizationCredentials | None,
            Depends(_bearer),
        ],
    ) -> Principal:
        principal = await self._principal_from_credentials(credentials)
        if principal.must_change_password:
            raise AuthError(
                AuthErrorCode.PASSWORD_CHANGE_REQUIRED,
                "Password change is required before using the application.",
                status_code=403,
            )
        return principal

    async def _principal_from_credentials(
        self,
        credentials: HTTPAuthorizationCredentials | None,
    ) -> Principal:
        if credentials is None or credentials.scheme.casefold() != "bearer":
            raise invalid_session()
        return await self.service.authenticate(credentials.credentials)

    def require_roles(self, *roles: str) -> Callable[..., Awaitable[Principal]]:
        async def dependency(
            principal: Annotated[Principal, Depends(self.authenticated)],
        ) -> Principal:
            self.service.require_roles(principal, *roles)
            return principal

        return dependency

    def require_scopes(self, *scopes: str) -> Callable[..., Awaitable[Principal]]:
        async def dependency(
            principal: Annotated[Principal, Depends(self.authenticated)],
        ) -> Principal:
            self.service.require_scopes(principal, *scopes)
            return principal

        return dependency

    def require_recent_authentication(
        self,
        *,
        max_age_seconds: int = 300,
    ) -> Callable[..., Awaitable[Principal]]:
        async def dependency(
            principal: Annotated[Principal, Depends(self.authenticated)],
        ) -> Principal:
            self.service.require_recent_authentication(
                principal,
                max_age_seconds=max_age_seconds,
            )
            return principal

        return dependency

    def protected_router(self, **kwargs: Any) -> APIRouter:
        dependencies = list(kwargs.pop("dependencies", []))
        dependencies.append(Depends(self.authenticated))
        return APIRouter(dependencies=dependencies, **kwargs)

    def _passkey_service(self) -> PasskeyService:
        if self.passkeys is not None:
            return self.passkeys
        try:
            from epok_auth.passkeys.webauthn import WebAuthnAdapter
        except ImportError as error:
            raise RuntimeError(
                'Passkeys require the optional dependency: uv add "epok-auth[passkeys]"'
            ) from error
        settings = self.settings
        if settings.passkey_rp_id is None:
            raise ValueError("passkey_rp_id is required when passkeys are enabled")
        adapter = WebAuthnAdapter(
            rp_id=settings.passkey_rp_id,
            rp_name=settings.effective_passkey_rp_name,
            timeout_ms=settings.passkey_timeout_ms,
        )
        self.passkeys = PasskeyService(
            store=cast(PasskeyStore, self.store),
            settings=settings,
            signer=self.service.signer,
            adapter=adapter,
            clock=self.service.clock,
        )
        return self.passkeys

    def _google_service(self) -> GoogleLoginService:
        if self.google is not None:
            return self.google
        if self.settings.google_client_id is None:
            raise ValueError("google_client_id is required when Google Sign-In is enabled")
        try:
            from epok_auth.google.google_auth import GoogleAuthVerifier
        except ImportError as error:  # pragma: no cover - isolated artifact smoke test
            raise RuntimeError('Google Sign-In requires: uv add "epok-auth[google]"') from error
        if self.google_store is None:
            raise ValueError(
                "google_store or a configured GoogleLoginService is required for Google Sign-In"
            )
        verifier = GoogleAuthVerifier(
            timeout_seconds=self.settings.google_token_timeout_seconds,
            max_credential_chars=self.settings.google_max_credential_chars,
        )
        self._resources.callback(verifier.close)
        self._owns_resources = True
        self.google = GoogleLoginService(
            store=self.google_store,
            settings=self.settings,
            signer=self.service.signer,
            verifier=verifier,
            passwords=self.service.passwords,
            clock=self.service.clock,
        )
        return self.google

    def _email_links(self) -> EmailLinkService:
        if self.email_link_service is not None:
            return self.email_link_service
        store = self.email_link_store or cast(EmailLinkStore, self.store)
        self.email_link_service = EmailLinkService(
            store=store,
            settings=self.settings,
            signer=self.service.signer,
            passwords=self.service.passwords,
            clock=self.service.clock,
        )
        return self.email_link_service

    def _email_mailer(self) -> EmailLinkMailer:
        if self._email_link_mailer is not None:
            return self._email_link_mailer
        sender = self.email_link_sender or SmtpEmailSender(SmtpSettings.from_env())
        self._email_link_mailer = EmailLinkMailer(self._email_links(), sender)
        return self._email_link_mailer

    def _email_dispatcher(self) -> EmailLinkDispatcher | None:
        if (
            self.settings.environment is Environment.PRODUCTION
            and self.email_link_dispatcher is None
        ):
            raise ValueError("production email links require a durable email_link_dispatcher")
        return self.email_link_dispatcher
