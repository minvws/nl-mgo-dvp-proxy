from app.forwarding.constants import DVA_TARGET_REQUEST_HEADER


class InvalidTargetUrlSignature(Exception):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("Signature verification failed; details: " + ", ".join(errors))


class MissingTargetUrlSignature(Exception):
    def __init__(self) -> None:
        super().__init__(f"Signature missing from: {DVA_TARGET_REQUEST_HEADER} header")


class SigningKeyNotLoaded(RuntimeError):
    def __init__(self) -> None:
        super().__init__("No public key loaded for verification")


class DisallowedTargetHost(Exception):
    def __init__(self, hostname: str) -> None:
        super().__init__(f"DVA target host '{hostname}' is disallowed by the blocklist")
