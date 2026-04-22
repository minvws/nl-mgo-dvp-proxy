from typing import Annotated, Dict, Self

from fastapi import Query
from httpx import AsyncClient
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
)

EXAMPLE_JWE = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0..."
NonBlankStr = Annotated[str, StringConstraints(min_length=1, strip_whitespace=True)]


class GetStateRequest(BaseModel):
    auth_endpoint_jwe: str = Field(
        ...,
        alias="authorization_server_url",
        description="A JWE containing a signed JWT which includes the authorization server URL as claim.",
        examples=[EXAMPLE_JWE],
    )
    token_endpoint_jwe: str = Field(
        ...,
        alias="token_endpoint_url",
        description="A JWE containing a signed JWT which includes the token server URL as claim.",
        examples=[EXAMPLE_JWE],
    )
    medmij_scope: str = Field(
        ...,
        description="The scope (zorgaanbieder_id) of the zorgaanbieder that access is being requested to.",
        examples=[
            "eenofanderezorgaanbieder",
        ],
    )
    client_target_url: str = Field(
        ...,
        description="The URL of the client application that can store the access_token data and correlation id.",
        examples=[
            "https://client.example.com/callback",
        ],
    )


class ParsedGetStateRequest(BaseModel):
    auth_endpoint_url: NonBlankStr
    token_endpoint_url: NonBlankStr
    medmij_scope: NonBlankStr
    client_target_url: NonBlankStr


class GetStateResponse(BaseModel):
    url_to_request: str = Field(
        description="The URL which a client can use to start the authentication flow.",
        examples=[
            "https://authorization-server.example.com/auth?state=xyz&client_id=123&response_type=code&redirect_uri=http%3A%2F%2Fclient.example.com%2Fcallback&scope=eenofanderezorgaanbieder",
        ],
    )


class StateDTO:
    def __init__(
        self, correlation_id: str, token_endpoint_url: str, client_target_url: str
    ) -> None:
        self.correlation_id: str = correlation_id
        self.token_endpoint_url: str = token_endpoint_url
        self.client_target_url: str = client_target_url
        self.expiration_time: int | None = None

    def set_expiration(self, exp: int) -> None:
        self.expiration_time = exp

    def to_dict(self) -> Dict[str, str | int | None]:
        return {
            "correlation_id": self.correlation_id,
            "token_endpoint_url": self.token_endpoint_url,
            "client_target_url": self.client_target_url,
            "expiration_time": self.expiration_time,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str | int | None]) -> Self:
        instance: Self = cls(
            correlation_id=str(data["correlation_id"]),
            token_endpoint_url=str(data["token_endpoint_url"]),
            client_target_url=str(data["client_target_url"]),
        )
        expiration_time = data.get("expiration_time")
        if expiration_time is not None:
            if isinstance(expiration_time, str):
                expiration_time = int(expiration_time)
            instance.set_expiration(expiration_time)
        return instance


class AccessTokenDTO(BaseModel):
    access_token: str = Field(
        ..., description="The access token issued by the authorization server."
    )
    token_type: str = Field(..., description="The type of the token issued.")
    expires_in: int = Field(
        ..., description="The lifetime in seconds of the access token."
    )
    refresh_token: str = Field(
        ...,
        description="The refresh token which can be used to obtain new access tokens.",
    )
    scope: str = Field(..., description="The scope of the access token.")

    @field_validator(
        "access_token", "token_type", "refresh_token", "scope", mode="before"
    )
    def not_empty(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is not None and not value.strip():
            raise ValueError(f'Property "{info.field_name}" may not be empty')
        return value

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
                "scope": "eenofanderezorgaanbieder",
            }
        }
    )


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
    token_endpoint_jwe: str = Query(
        ...,
        alias="token_endpoint_url",
        description="A JWE containing a signed JWT which includes the token server URL as claim.",
        examples=[EXAMPLE_JWE],
    )
    refresh_token: str = Query(
        ...,
        description="Authorization refresh code.",
        examples=["tGzv3JOkF0XG5Qx2TlKWIA"],
    )
    correlation_id: str = Query(
        ...,
        description="""A UUID which is linked to the authorization session and which should be
            equal to the X-Correlation-id sent during authorization.""",
        examples=["123e4567-e89b-12d3-a456-426614174000"],
    )


class ParsedOAuthRefreshRequest(BaseModel):
    token_endpoint_url: NonBlankStr
    refresh_token: NonBlankStr
    correlation_id: NonBlankStr


class AsyncOAuthClient(AsyncClient):
    pass
