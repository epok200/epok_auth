from datetime import datetime
from typing import Annotated, Literal, Protocol
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field, SecretStr

from epok_auth import EpokAuth, Principal, Reauthentication


class RestoreIntent(BaseModel):
    purpose: Literal["resource.restore"] = "resource.restore"
    resource_id: UUID
    target_id: UUID
    expected_revision: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=500)


class PasswordReauthenticationRequest(BaseModel):
    password: SecretStr
    intent: RestoreIntent


class PasskeyReauthenticationRequest(BaseModel):
    ceremony_id: UUID
    credential: dict[str, object]
    intent: RestoreIntent


class PasskeyOptionsResponse(BaseModel):
    ceremony_id: UUID
    public_key: dict[str, object]


class ConfirmationResponse(BaseModel):
    confirmation_id: UUID
    expires_at: datetime


class RestoreConfirmationIssuer(Protocol):
    async def issue_restore(
        self,
        proof: Reauthentication,
        intent: RestoreIntent,
    ) -> ConfirmationResponse: ...


def create_reauthentication_router(
    auth: EpokAuth,
    confirmations: RestoreConfirmationIssuer,
) -> APIRouter:
    router = APIRouter(prefix="/reauthentication", tags=["reauthentication"])

    @router.post("/passkey/options")
    async def passkey_options(
        request: Request,
        response: Response,
        principal: Annotated[Principal, Depends(auth.authenticated)],
    ) -> PasskeyOptionsResponse:
        options = await auth.passkey_service.begin_reauthentication(
            principal,
            request.headers.get("origin"),
        )
        auth.http.disable_cache(response)
        return PasskeyOptionsResponse(
            ceremony_id=options.ceremony_id,
            public_key=options.public_key,
        )

    @router.post("/password")
    async def reauthenticate_password(
        payload: PasswordReauthenticationRequest,
        request: Request,
        response: Response,
        principal: Annotated[Principal, Depends(auth.authenticated)],
    ) -> ConfirmationResponse:
        auth.service.validate_origin(request.headers.get("origin"))
        proof = await auth.service.reauthenticate_password(
            principal,
            payload.password.get_secret_value(),
            context=auth.http.request_context(request),
        )
        confirmation = await confirmations.issue_restore(proof, payload.intent)
        auth.http.disable_cache(response)
        return confirmation

    @router.post("/passkey")
    async def reauthenticate_passkey(
        payload: PasskeyReauthenticationRequest,
        request: Request,
        response: Response,
        principal: Annotated[Principal, Depends(auth.authenticated)],
    ) -> ConfirmationResponse:
        proof = await auth.passkey_service.finish_reauthentication(
            principal,
            payload.ceremony_id,
            payload.credential,
            request.headers.get("origin"),
            context=auth.http.request_context(request),
        )
        confirmation = await confirmations.issue_restore(proof, payload.intent)
        auth.http.disable_cache(response)
        return confirmation

    return router
