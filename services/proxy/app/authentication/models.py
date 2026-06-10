from dataclasses import dataclass

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
)


@dataclass(frozen=True)
class StateDTO:
    correlation_id: str
    token_endpoint_url: str
    client_target_url: str
    expiration_time: int


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
