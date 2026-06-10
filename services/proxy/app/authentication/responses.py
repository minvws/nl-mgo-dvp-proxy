from typing import Any

from fastapi.responses import JSONResponse, Response


class RequestValidationFailedResponse(JSONResponse):
    def __init__(self, detail: Any) -> None:
        super().__init__(content={"detail": detail}, status_code=422)


class OAuthFailureResponse(Response):
    pass
