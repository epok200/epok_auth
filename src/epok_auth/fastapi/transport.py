from datetime import UTC, datetime
from typing import Any

from fastapi import Request, Response

from epok_auth.config import AuthSettings
from epok_auth.models import RequestContext, SessionBundle

type CookieParameters = dict[str, Any]


class AuthHttpTransport:
    """Owns authentication cookies and request metadata at the HTTP boundary."""

    def __init__(self, settings: AuthSettings) -> None:
        self.settings = settings

    def set_session_cookies(self, response: Response, bundle: SessionBundle) -> None:
        now = datetime.now(UTC)
        max_age = max(
            0,
            int(
                min(bundle.refresh_idle_expires_at, bundle.refresh_absolute_expires_at).timestamp()
                - now.timestamp()
            ),
        )
        common: CookieParameters = {
            "max_age": max_age,
            "expires": bundle.refresh_absolute_expires_at,
            "path": self.settings.cookie_path,
            "domain": self.settings.cookie_domain,
            "secure": self.settings.secure_cookies,
            "samesite": self.settings.cookie_same_site,
        }
        response.set_cookie(
            self.settings.effective_refresh_cookie_name,
            bundle.refresh_token,
            httponly=True,
            **common,
        )
        response.set_cookie(
            self.settings.effective_csrf_cookie_name,
            bundle.csrf_token,
            httponly=self.settings.csrf_cookie_http_only,
            **common,
        )

    def delete_session_cookies(self, response: Response) -> None:
        response.delete_cookie(
            self.settings.effective_refresh_cookie_name,
            path=self.settings.cookie_path,
            domain=self.settings.cookie_domain,
            secure=self.settings.secure_cookies,
            httponly=True,
            samesite=self.settings.cookie_same_site,
        )
        response.delete_cookie(
            self.settings.effective_csrf_cookie_name,
            path=self.settings.cookie_path,
            domain=self.settings.cookie_domain,
            secure=self.settings.secure_cookies,
            httponly=self.settings.csrf_cookie_http_only,
            samesite=self.settings.cookie_same_site,
        )

    def set_email_link_cookie(self, response: Response, nonce: str) -> None:
        response.set_cookie(
            self.settings.effective_email_link_cookie_name,
            nonce,
            max_age=self.settings.email_link_login_ttl_seconds,
            path=self.settings.cookie_path,
            domain=self.settings.cookie_domain,
            secure=self.settings.secure_cookies,
            httponly=True,
            samesite="lax",
        )

    def delete_email_link_cookie(self, response: Response) -> None:
        response.delete_cookie(
            self.settings.effective_email_link_cookie_name,
            path=self.settings.cookie_path,
            domain=self.settings.cookie_domain,
            secure=self.settings.secure_cookies,
            httponly=True,
            samesite="lax",
        )

    @staticmethod
    def disable_cache(response: Response) -> None:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"

    @staticmethod
    def request_context(request: Request) -> RequestContext:
        request_id = getattr(request.state, "request_id", None) or request.headers.get(
            "x-request-id"
        )
        if request_id is not None:
            request_id = str(request_id)

        ip_address = request.client.host if request.client is not None else None
        return RequestContext(
            request_id=request_id,
            ip_address=ip_address,
            user_agent=request.headers.get("user-agent"),
        )
