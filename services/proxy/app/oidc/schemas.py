from enum import Enum
from typing import Any

from fastapi import Query
from pydantic import AnyHttpUrl, AnyUrl, BaseModel, Field


class StartRequest(BaseModel):  # pragma: no cover
    client_callback_url: AnyUrl = Field(
        ...,
        description="The URL where the userinfo response (i.e. RID, personal details) is forwarded to",
        examples=[
            "https://client.app/oidc/userinfo/callback",
        ],
    )


class StartResponse(BaseModel):  # pragma: no cover
    authz_url: AnyHttpUrl = Field(
        ..., description="The URL to the VAD authorization endpoint"
    )


class ContinueRequest(BaseModel):  # pragma: no cover
    code: str = Query(..., description="The authorization code received from the VAD")
    state: str = Query(..., description="The encrypted state owned by the DVP Proxy")


class VadTokenResponse(BaseModel):  # pragma: no cover
    access_token: str = Field(
        ..., description="The access token used to fetch the userinfo"
    )
    token_type: str = Field(..., description="The type of token", examples=["Bearer"])
    expires_in: int = Field(
        ..., description="The time in seconds until the token expires"
    )


class VadUserinfoResponse(BaseModel):  # pragma: no cover
    rid: str = Field(
        ...,
        description="The Reference ID (RID) generated for the client",
    )
    person: dict[str, Any] = Field(
        ...,
        description="A JSON object with two properties: `age` (optional) and `name` (JSON object with optional name parts)",
    )
    sub: str = Field(description="Subject identifier containing the auth session id.")


class State(BaseModel):  # pragma: no cover
    client_callback_url: str
    code_verifier: str


class VadOidcConfiguration(BaseModel):  # pragma: no cover
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    scopes_supported: list[str]
    response_types_supported: list[str]
    response_modes_supported: list[str]
    grant_types_supported: list[str]
    subject_types_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    claims_parameter_supported: bool
    userinfo_endpoint: str


class TokenGrantType(str, Enum):  # pragma: no cover
    AUTHZ_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
