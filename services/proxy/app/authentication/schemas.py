from dataclasses import dataclass
from typing import Annotated

from fastapi import Query
from fastapi.responses import RedirectResponse
from pydantic import (
    BaseModel,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
)

EXAMPLE_JWE = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0..."
NonBlankStr = Annotated[str, StringConstraints(min_length=1, strip_whitespace=True)]


class GetStateRequest(BaseModel):
    auth_endpoint_jwe: NonBlankStr = Field(
        ...,
        alias="authorization_server_url",
        description="A JWE containing a signed JWT which includes the authorization server URL as claim.",
        examples=[EXAMPLE_JWE],
    )
    token_endpoint_jwe: NonBlankStr = Field(
        ...,
        alias="token_endpoint_url",
        description="A JWE containing a signed JWT which includes the token server URL as claim.",
        examples=[EXAMPLE_JWE],
    )
    medmij_scope: NonBlankStr = Field(
        ...,
        description="The scope (zorgaanbieder_id) of the zorgaanbieder that access is being requested to.",
        examples=[
            "eenofanderezorgaanbieder",
        ],
    )
    client_target_url: NonBlankStr = Field(
        ...,
        description="The URL of the client application that can store the access_token data and correlation id.",
        examples=[
            "https://client.example.com/callback",
        ],
    )


@dataclass(frozen=True)
class ParsedGetStateRequest:
    payload: GetStateRequest
    auth_endpoint_url: str
    token_endpoint_url: str


class OAuthCallbackRequest(BaseModel):
    error: int | None = Query(default=None, description="Error code if any.")
    error_description: str | None = Query(
        default=None, description="Description of the error."
    )
    error_uri: str | None = Query(
        default=None,
        description="A URI identifying a human-readable web page with information about the error.",
    )
    code: str | None = Query(default=None, description="Authorization code.")
    state: str | None = Query(
        default=None,
        description="State parameter to maintain state between request and callback.",
    )

    @field_validator("code", "state", mode="before")
    def not_empty(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is not None and not value.strip():
            raise ValueError(f'Property "{info.field_name}" may not be empty')
        return value


class OAuthRefreshRequest(BaseModel):
    token_endpoint_jwe: NonBlankStr = Query(
        ...,
        alias="token_endpoint_url",
        description="A JWE containing a signed JWT which includes the token server URL as claim.",
        examples=[EXAMPLE_JWE],
    )
    refresh_token: NonBlankStr = Query(
        ...,
        description="Authorization refresh code.",
        examples=["tGzv3JOkF0XG5Qx2TlKWIA"],
    )
    correlation_id: NonBlankStr = Query(
        ...,
        description="""A UUID which is linked to the authorization session and which should be
            equal to the X-Correlation-id sent during authorization.""",
        examples=["123e4567-e89b-12d3-a456-426614174000"],
    )


@dataclass(frozen=True)
class ParsedOAuthRefreshRequest:
    payload: OAuthRefreshRequest
    token_endpoint_url: str


class GetStateResponse(BaseModel):
    url_to_request: str = Field(
        description="The URL which a client can use to start the authentication flow.",
        examples=[
            "https://authorization-server.example.com/auth?state=xyz&client_id=123&response_type=code&redirect_uri=http%3A%2F%2Fclient.example.com%2Fcallback&scope=eenofanderezorgaanbieder",
        ],
    )


class AuthorizationAccessTokenCallbackRedirectResponse(RedirectResponse):
    redirect_url: str = Field(
        description="The URL (client_target_url) to redirect the user to store the access_token and the refresh_token.",
        examples=[
            "https://client.example.com/callback?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9&token_type=Bearer&expires_in=900&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA&scope=51+52",
        ],
    )

    def __init__(self, redirect_url: str):
        super().__init__(url=redirect_url)
