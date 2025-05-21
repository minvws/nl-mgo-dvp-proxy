from typing import Any

from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import Field


class AuthorizationAccessTokenCallbackRedirectResponse(RedirectResponse):
    redirect_url: str = Field(
        description="The URL (client_target_url) to redirect the user to store the access_token and the refresh_token.",
        examples=[
            "https://client.example.com/callback?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9&token_type=Bearer&expires_in=900&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA&scope=51+52",
        ],
    )

    def __init__(self, redirect_url: str):
        super().__init__(url=redirect_url)


class RequestValidationFailedResponse(JSONResponse):
    def __init__(self, detail: Any) -> None:
        super().__init__(content={"detail": detail}, status_code=422)


class OAuthFailureResponse(Response):
    pass
