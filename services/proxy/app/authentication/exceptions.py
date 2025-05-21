from typing import Any

from fastapi import HTTPException


class MedMijOAuthException(Exception):
    pass


class MedMijStateException(MedMijOAuthException):
    pass


class ExpiredStateException(MedMijStateException):
    pass


class ExpirationTimeMissingException(MedMijStateException):
    pass


class ExpirationTimeTypeException(MedMijStateException):
    pass


class InvalidStateException(MedMijStateException):
    pass


class AuthorizationHttpException(HTTPException):
    pass


class RequestValidationException(Exception):
    def __init__(self, detail: list[dict[str, Any]]) -> None:
        self.detail = detail
        super().__init__()
