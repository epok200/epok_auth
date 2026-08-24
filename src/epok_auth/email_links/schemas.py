from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints

EmailInput = Annotated[str, StringConstraints(min_length=3, max_length=320)]
LinkToken = Annotated[str, StringConstraints(min_length=1, max_length=512)]
PasswordInput = Annotated[str, StringConstraints(min_length=1, max_length=1024)]


class StrictEmailLinkSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RequestEmailLink(StrictEmailLinkSchema):
    email: EmailInput


class ConsumeEmailLink(StrictEmailLinkSchema):
    token: LinkToken


class ConsumePasswordReset(ConsumeEmailLink):
    new_password: PasswordInput


class EmailLinkAccepted(BaseModel):
    accepted: Literal[True] = True
