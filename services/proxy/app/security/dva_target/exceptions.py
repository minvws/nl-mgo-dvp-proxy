class DvaTargetAssertionError(Exception):
    pass


class JWEDecryptError(DvaTargetAssertionError):
    pass


class JWTValidationError(DvaTargetAssertionError):
    pass


class JWTClaimsError(DvaTargetAssertionError):
    pass
