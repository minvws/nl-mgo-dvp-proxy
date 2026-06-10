from typing import Any


class DvaTargetAssertionError(Exception):
    def __init__(self, *args: object, error_context: dict[str, Any]) -> None:
        super().__init__(*args)
        self.error_context = error_context


class JWEDecryptError(DvaTargetAssertionError):
    pass


class JWTValidationError(DvaTargetAssertionError):
    pass


class JWTClaimsError(DvaTargetAssertionError):
    pass
