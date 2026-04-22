import json
import logging
import time
from typing import Set
from urllib.parse import urlsplit

from jwcrypto.common import JWException
from jwcrypto.jwe import JWE
from jwcrypto.jwt import JWT

from app.security.dva_target.exceptions import (
    JWEDecryptError,
    JWTClaimsError,
    JWTValidationError,
)
from app.security.repositories import JWKRepository

logger = logging.getLogger(__name__)


class DvaTargetAssertionParser:
    JWE_DECRYPTION_KID: str = "jwe_decryption_kid"
    JWT_SIGNATURE_VALIDATION_KID: str = "jwt_signature_validation_kid"

    def __init__(self, jwk_repository: JWKRepository, blocklist: Set[str]) -> None:
        self.__jwk_repository = jwk_repository
        self.__blocklist = blocklist

    def parse(self, serialized_jwe: str) -> str:
        """
        Parser service to extract and validate the DVA target URL from a serialized JWE containing a signed JWT as payload.
        The extraction is done in the following steps:
        1. Decrypt the JWE to obtain the serialized JWT.
        2. Validate the JWT signature and claims (e.g. expiration).
        3. Extract the DVA target URL from the 'url' claim in the JWT
        4. Assert the DVA target URL is not on the blocklist

        :param serialized_jwe: serialized JWE containing a signed JWT with the DVA target URL as claim
        :return: plain DVA target URL extracted from the JWE
        """
        try:
            jwe = JWE()

            jwe.deserialize(serialized_jwe)
            jwe.decrypt(
                self.__jwk_repository.get_first_key_from_store(self.JWE_DECRYPTION_KID)
            )

            serialized_jwt = jwe.payload.decode("utf-8")
        except JWException as exc:
            logger.error("Encountered error during JWE decryption: %s", exc)
            raise JWEDecryptError(str(exc)) from exc

        now = int(time.time())
        jwt_signature_validation_key = self.__jwk_repository.get_first_key_from_store(
            self.JWT_SIGNATURE_VALIDATION_KID
        )

        try:
            jwt = JWT(
                jwt=serialized_jwt,
                key=jwt_signature_validation_key,
                check_claims={
                    # The library states it checks exact values when using checked claims, but this is a magic claim (next to nbf) that is actually checked
                    # for being present AND having a value less than or equal to the current time. Thus making it "magic".
                    "exp": now,
                    # Non magic claim that can only be checked manually, but this guarantees that the iat claim is at least present in the token.
                    "iat": None,
                },
            )
            jwt.validate(jwt_signature_validation_key)
        except JWException as exc:
            logger.error("Encountered error during JWT validation: %s", exc)
            raise JWTValidationError(str(exc)) from exc

        try:
            dva_target_url: str = json.loads(jwt.claims)["url"]
        except KeyError as exc:
            raise JWTClaimsError("Missing 'url' claim in JWT") from exc

        if not isinstance(dva_target_url, str):
            raise JWTClaimsError("The 'url' claim must be a string")

        dva_target_hostname = urlsplit(dva_target_url).hostname or ""
        if dva_target_hostname in self.__blocklist:
            logger.warning("DVA target hostname blocked: %s", dva_target_hostname)

            raise JWTClaimsError("The DVA target host is blocked")

        return dva_target_url
