from logging import Logger

import inject
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from app.authentication.exceptions import (
    AuthorizationHttpException,
    MedMijOAuthException,
    RequestValidationException,
)
from app.authentication.responses import (
    OAuthFailureResponse,
    RequestValidationFailedResponse,
)


class ExceptionHandlers:
    @staticmethod
    def load_handlers(app: FastAPI) -> None:
        # Custom exception handler for RequestValidationError
        @app.exception_handler(RequestValidationError)
        @app.exception_handler(RequestValidationException)
        @inject.autoparams()
        async def validation_exception_handler(
            request: Request,
            exc: RequestValidationError | RequestValidationException,
            logger: Logger,
        ) -> JSONResponse:
            errors = (
                exc.errors() if isinstance(exc, RequestValidationError) else exc.detail
            )
            logger.error(msg=f"Request validation failed: 422 - {errors}")
            return RequestValidationFailedResponse(detail=errors)

        @app.exception_handler(MedMijOAuthException)
        @inject.autoparams()
        async def medmij_exception_handler(
            request: Request, exc: MedMijOAuthException, logger: Logger
        ) -> JSONResponse:
            logger.error(msg=f"MedMij OAuth Exception: {str(exc)}")

            return JSONResponse(
                status_code=HTTP_400_BAD_REQUEST,
                content={"status_code": HTTP_400_BAD_REQUEST, "detail": str(exc)},
            )

        @app.exception_handler(AuthorizationHttpException)
        @inject.autoparams()
        async def authorization_exception_handler(
            request: Request, exc: AuthorizationHttpException, logger: Logger
        ) -> Response:
            logger.error(
                msg=f"Authorization exception: {exc.status_code} - {exc.detail}"
            )

            return OAuthFailureResponse(status_code=502, content="Bad Gateway")

        @app.exception_handler(Exception)
        @inject.autoparams()
        async def general_exception_handler(
            request: Request, exc: Exception, logger: Logger
        ) -> JSONResponse:
            return JSONResponse(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal Server Error"},
            )
