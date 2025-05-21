from logging import Logger
from typing import List
from urllib.parse import urlsplit

import anyio
import inject
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    EllipticCurveSignatureAlgorithm,
)

from app.config.models import AppConfig
from app.forwarding.models import DvaTarget, TargetUrlSignature

from .exceptions import (
    DisallowedTargetHost,
    InvalidTargetUrlSignature,
    MissingTargetUrlSignature,
    SigningKeyNotLoaded,
)


class SignedUrlVerifier:
    public_keys: List[EllipticCurvePublicKey] = []
    public_key_paths: List[str]

    def __init__(
        self,
        public_key_paths: List[str],
        signature_algorithm: EllipticCurveSignatureAlgorithm,
    ) -> None:
        self.public_key_paths = public_key_paths
        self.signature_algorithm = signature_algorithm

    async def load_public_keys(self) -> None:
        if len(self.public_keys) > 0:
            return

        self.public_keys = []

        async with anyio.create_task_group() as tg:
            for key_path in self.public_key_paths:
                tg.start_soon(self._load_public_key, key_path)

    async def _load_public_key(self, key_path: str) -> None:
        async with await anyio.open_file(key_path, "rb") as key_file:
            key_data = await key_file.read()
            loaded_key = serialization.load_pem_public_key(key_data)

            if not isinstance(loaded_key, EllipticCurvePublicKey):
                raise TypeError("Public key is not of type EllipticCurvePublicKey")

            self.public_keys.append(loaded_key)

    def verify(self, url: str, signature: TargetUrlSignature) -> None:
        errors: List[str] = []

        if len(self.public_keys) == 0:
            raise SigningKeyNotLoaded()

        for idx, public_key in enumerate(self.public_keys):
            try:
                public_key.verify(
                    signature.decode(),
                    url.encode(),
                    self.signature_algorithm,
                )
            except InvalidSignature:
                errors.append(f"Public key {idx} failed verification.")
            except Exception as e:
                errors.append(f"Unexpected error with public key {idx}: {str(e)}")

        if errors:
            raise InvalidTargetUrlSignature(errors)


class DvaTargetVerifier:
    @inject.autoparams()
    def __init__(
        self,
        app_config: AppConfig,
        signed_url_verifier: SignedUrlVerifier,
        logger: Logger,
    ) -> None:
        self.verify_signed_requests = (
            app_config.signature_validation.verify_signed_requests
        )
        self.dva_target_host_blocklist = app_config.dva_target.host_blocklist
        self.signed_url_verifier = signed_url_verifier
        self.logger = logger

    async def verify(self, dva_target: DvaTarget) -> None:
        self.__verify_dva_target_host(dva_target.target_url)

        if not dva_target.signature:
            self.__handle_missing_signature()
            return

        if not self.verify_signed_requests:
            self.logger.info("Skipped verification of dva target url")
            return

        await self.signed_url_verifier.load_public_keys()

        self.signed_url_verifier.verify(
            url=dva_target.target_url,
            signature=dva_target.signature,
        )

    def __handle_missing_signature(self) -> None:
        if self.verify_signed_requests:
            raise MissingTargetUrlSignature()

        self.logger.info("Ignored missing signature from dva target url")

    def __verify_dva_target_host(self, dva_target_url: str) -> None:
        target_host = urlsplit(dva_target_url).hostname or ""
        host_allowed = target_host not in self.dva_target_host_blocklist
        log_message_template = "DVA target host verification %s"

        if not host_allowed:
            self.logger.warning(
                log_message_template + " for host '%s'", "failed", target_host
            )

            raise DisallowedTargetHost(target_host)

        self.logger.debug(log_message_template, "passed")
