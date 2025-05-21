from base64 import urlsafe_b64encode
from hashlib import sha256
from secrets import token_hex, token_urlsafe
from time import time
from typing import Any
from urllib.parse import urlsplit

from inject import autoparams
from jwcrypto import jwk, jwt

from app.config.models import OidcConfig
from app.security.repositories import KeyStoreRepository
from app.security.services import Encrypter

from .clients import VadHttpClient
from .constants import (
    VAD_OIDC_CLIENT_ASSERTION_TYPE,
    VAD_OIDC_CODE_CHALLENGE_METHOD,
    VAD_OIDC_RESPONSE_TYPE,
    VAD_OIDC_SCOPE,
)
from .repositories import VadOidcConfigRepository
from .schemas import State, TokenGrantType, VadUserinfoResponse


class PkceCodePairGenerator:
    CODE_VERIFIER_LENGTH: int = 128  # Must be between 43 and 128 characters.

    def generate(self) -> tuple[str, str]:
        """
        Generate a code verifier and code challenge for PKCE.

        :return: A tuple containing the code verifier and code challenge.
        """
        code_verifier = self.__generate_code_verifier()
        code_challenge = self.__generate_code_challenge(code_verifier)

        return (
            code_verifier,
            code_challenge,
        )

    def __generate_code_verifier(self) -> str:
        if not 43 <= self.CODE_VERIFIER_LENGTH <= 128:
            raise ValueError(
                "Code verifier must be between 43 and 128 characters long."
            )

        return token_urlsafe(96)[: self.CODE_VERIFIER_LENGTH]

    def __generate_code_challenge(self, code_verifier: str) -> str:
        hashed = sha256(code_verifier.encode("ascii")).digest()
        encoded = urlsafe_b64encode(hashed)

        # Remove padding from b64 encoding
        code_challenge = encoded.decode("ascii")[:-1]

        return code_challenge


class ClientAssertionJwtIssuer:
    KEY_STORE_PVT_KEY_ID: str = "client_assertion_jwt_pvt_key"
    KEY_STORE_PUB_KEY_ID: str = "client_assertion_jwt_pub_key"
    JWT_ALG: str = "RS256"
    DEFAULT_JWT_EXP = 60
    DEFAULT_JWT_NBF = 10

    @autoparams("key_store_repository")
    def __init__(
        self,
        key_store_repository: KeyStoreRepository,
    ):
        self.__key_store_repository = key_store_repository
        self.__private_key: jwk.JWK | None = None
        self.__public_key: jwk.JWK | None = None

    def create(self, payload: dict[str, Any]) -> jwt.JWT:
        private_key = self.__get_private_key()
        public_key = self.__get_public_key()

        new_jwt = jwt.JWT(
            header={
                "alg": self.JWT_ALG,
                "x5t": private_key.thumbprint(),
                "kid": public_key.thumbprint(),
            },
            claims={
                **{
                    "nbf": int(time()) - self.DEFAULT_JWT_NBF,
                    "exp": int(time()) + self.DEFAULT_JWT_EXP,
                },
                **payload,
            },
        )
        new_jwt.make_signed_token(private_key)

        return new_jwt

    def __get_private_key(self) -> jwk.JWK:
        if self.__private_key is None:
            self.__private_key = jwk.JWK.from_pem(
                self.__key_store_repository.get_key_store(self.KEY_STORE_PVT_KEY_ID)[0],
                password=None,
            )

        return self.__private_key

    def __get_public_key(self) -> jwk.JWK:
        if self.__public_key is None:
            self.__public_key = jwk.JWK.from_pem(
                self.__key_store_repository.get_key_store(self.KEY_STORE_PUB_KEY_ID)[0],
                password=None,
            )

        return self.__public_key


class VadAuthorizationUrlProvider:
    @autoparams(
        "config", "vad_oidc_repository", "pkce_code_pair_generator", "encrypter"
    )
    def __init__(
        self,
        base_url: str,
        config: OidcConfig,
        vad_oidc_repository: VadOidcConfigRepository,
        pkce_code_pair_generator: PkceCodePairGenerator,
        encrypter: Encrypter,
    ):
        self.__client_id: str = config.client_id
        self.__callback_url: str = (
            base_url.rstrip("/") + "/" + config.callback_endpoint.lstrip("/")
        )
        self.__vad_oidc_config_repository = vad_oidc_repository
        self.__pkce_code_pair_generator = pkce_code_pair_generator
        self.__encrypter = encrypter

    def invoke(self, client_callback_url: str) -> str:
        authz_endpoint = (
            self.__vad_oidc_config_repository.get_all().authorization_endpoint
        )
        code_verifier, code_challenge = self.__pkce_code_pair_generator.generate()
        state = State(
            client_callback_url=client_callback_url, code_verifier=code_verifier
        )
        encrypted_state = self.__encrypter.encrypt(state.model_dump_json())

        return (
            "%s?response_type=%s&client_id=%s&redirect_uri=%s&scope=%s&state=%s&code_challenge=%s&code_challenge_method=%s&nonce=%s"
            % (
                authz_endpoint,
                VAD_OIDC_RESPONSE_TYPE,
                self.__client_id,
                self.__callback_url,
                VAD_OIDC_SCOPE,
                encrypted_state,
                code_challenge,
                VAD_OIDC_CODE_CHALLENGE_METHOD,
                token_hex(16),
            )
        )


class VadUserinfoProvider:
    @autoparams("config", "vad_oidc_repository", "vad_http_client", "jwt_issuer")
    def __init__(
        self,
        base_url: str,
        config: OidcConfig,
        vad_oidc_repository: VadOidcConfigRepository,
        vad_http_client: VadHttpClient,
        jwt_issuer: ClientAssertionJwtIssuer,
    ):
        self.__client_id: str = config.client_id
        self.__callback_url: str = (
            base_url.rstrip("/") + "/" + config.callback_endpoint.lstrip("/")
        )
        self.__vad_oidc_config_repository = vad_oidc_repository
        self.__vad_http_client = vad_http_client
        self.__jwt_issuer = jwt_issuer

    def invoke(self, authz_code: str, state: State) -> VadUserinfoResponse:
        vad_oidc_config = self.__vad_oidc_config_repository.get_all()
        token_endpoint = urlsplit(vad_oidc_config.token_endpoint).path
        token_url = vad_oidc_config.token_endpoint
        userinfo_endpoint = urlsplit(vad_oidc_config.userinfo_endpoint).path

        client_assertion_jwt = self.__jwt_issuer.create(
            {"iss": self.__client_id, "sub": self.__client_id, "aud": token_url}
        )

        token_response = self.__vad_http_client.post_authz_code(
            endpoint=token_endpoint,
            grant_type=TokenGrantType.AUTHZ_CODE,
            authz_code=authz_code,
            redirect_uri=self.__callback_url,
            code_verifier=state.code_verifier,
            client_id=self.__client_id,
            client_assertion=str(client_assertion_jwt),
            client_assertion_type=VAD_OIDC_CLIENT_ASSERTION_TYPE,
        )

        userinfo_response = self.__vad_http_client.get_userinfo(
            endpoint=userinfo_endpoint,
            access_token=token_response.access_token,
        )

        return VadUserinfoResponse(**userinfo_response.json())


class ClientCallbackUrlDecorator:
    def decorate_with_userinfo_data(
        self, userinfo: VadUserinfoResponse, state: State
    ) -> str:
        client_callback_url = state.client_callback_url
        userinfo_query_params = urlsafe_b64encode(
            userinfo.model_dump_json().encode()
        ).decode()
        query_delimiter = "&" if "?" in client_callback_url else "?"

        return f"{client_callback_url}{query_delimiter}userinfo={userinfo_query_params}"
