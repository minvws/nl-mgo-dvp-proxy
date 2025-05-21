import json
import time
import uuid
from typing import List
from urllib import parse

import inject
from cryptography.fernet import Fernet, InvalidToken

from app.forwarding.constants import TARGET_URL_SIGNATURE_QUERY_PARAM
from app.medmij_logging.enums import GrantType
from app.medmij_logging.factories import LogMessageFactory
from app.medmij_logging.services import MedMijLogger, ServerIdentifier
from app.utils import resolve_instance

from .exceptions import (
    ExpirationTimeMissingException,
    ExpirationTimeTypeException,
    ExpiredStateException,
    InvalidStateException,
)
from .interfaces import OauthTokenAdapter
from .models import AccessTokenDTO, StateDTO


class StateService:
    def __init__(self, signing_keys: List[bytes], signature_lifetime_secs: int) -> None:
        self.__keys: List[bytes] = signing_keys
        self.__signature_lifetime_secs: int = signature_lifetime_secs

    def __attempt_decrypt(self, encrypted_message: str) -> bytes:
        """
        Loop through all keys and attempt to decrypt the message,
        return the decrypted message if successful,
        raise an exception otherwise.
        """
        for key in self.__keys:
            try:
                cipher_suite: Fernet = Fernet(key)
                decrypted_message: bytes = cipher_suite.decrypt(encrypted_message)

            except InvalidToken:
                raise InvalidStateException("Could not decrypt state")

        return decrypted_message

    def generate_state_token(self, state_dto: StateDTO) -> str:
        cipher_suite: Fernet = Fernet(self.__keys[0])

        now = int(time.time())
        state_dto.set_expiration(now + self.__signature_lifetime_secs)

        message: str = json.dumps(state_dto.to_dict())
        encrypted_message: bytes = cipher_suite.encrypt(message.encode())

        return encrypted_message.decode("utf-8")

    def decrypt_state_token(self, token: str) -> StateDTO:
        data_string: bytes = self.__attempt_decrypt(token)
        data: dict[str, str | int | None] = json.loads(data_string.decode("utf-8"))
        exp: int | str | None = data.get("expiration_time")

        if exp is None:
            raise ExpirationTimeMissingException(
                "No expiration time found in State token"
            )

        if not isinstance(exp, int):
            raise ExpirationTimeTypeException("Expiration time is not an integer")

        current_time: int = int(time.time())

        if current_time > int(exp):
            raise ExpiredStateException("State token has expired")

        return StateDTO.from_dict(data)

    def verify_state_token(self, token: str) -> None:
        self.decrypt_state_token(token=token)


class UrlBuilder:
    def __init__(self) -> None:
        self._params: dict[str, str] = {}

    def add_param(self, name: str, value: str) -> None:
        self._params[name] = value

    def __reset(self) -> None:
        self._params = {}

    def build(self, location: str) -> str:
        if "?" in location:
            location += "&"
        else:
            location += "?"

        location += "&".join([f"{k}={v}" for k, v in self._params.items()])

        self.__reset()

        return location


class MedMijAuthRequestUrlDirector:
    @inject.autoparams("builder", "state_service")
    def __init__(
        self,
        builder: UrlBuilder,
        state_service: StateService,
        client_id: str,
        redirect_url: str,
    ) -> None:
        self._builder: UrlBuilder = builder
        self.__state_service: StateService = state_service
        self._client_id: str = client_id
        self._redirect_url: str = redirect_url

    def add_medmij_id(self) -> None:
        medmij_id: str = str(uuid.uuid4())
        self._builder.add_param("MedMij-Request-ID", medmij_id)

    def add_correlation_id(self, correlation_id: str) -> None:
        self._builder.add_param("X-Correlation-ID", correlation_id)

    def add_state(
        self, correlation_id: str, token_endpoint_url: str, client_target_url: str
    ) -> None:
        token_endpoint_url_without_signature: str = self.__pop_off_signature(
            token_endpoint_url=token_endpoint_url
        )

        initial_state = StateDTO(
            correlation_id=correlation_id,
            token_endpoint_url=token_endpoint_url_without_signature,
            client_target_url=client_target_url,
        )

        state: str = self.__state_service.generate_state_token(state_dto=initial_state)
        self._builder.add_param(name="state", value=state)

    def add_client_id(self) -> None:
        self._builder.add_param("client_id", self._client_id)

    def add_response_type(self) -> None:
        self._builder.add_param("response_type", "code")

    def add_redirect_uri(self) -> None:
        self._builder.add_param("redirect_uri", parse.quote(self._redirect_url))

    def add_scope(self, scope: str) -> None:
        self._builder.add_param("scope", scope)

    def build_authorization_request_url(
        self,
        authorization_server_url: str,
        token_endpoint_url: str,
        client_target_url: str,
        scope: str,
    ) -> str:
        correlation_id: str = str(uuid.uuid4())

        self.add_state(
            correlation_id=correlation_id,
            token_endpoint_url=token_endpoint_url,
            client_target_url=client_target_url,
        )
        self.add_correlation_id(correlation_id=correlation_id)
        self.add_scope(scope=scope)
        self.add_client_id()
        self.add_medmij_id()
        self.add_response_type()
        self.add_redirect_uri()

        return self._builder.build(location=authorization_server_url)

    def __pop_off_signature(self, token_endpoint_url: str) -> str:
        parsed_url = parse.urlparse(token_endpoint_url)
        query_params = parse.parse_qs(parsed_url.query)
        query_params.pop(TARGET_URL_SIGNATURE_QUERY_PARAM, None)

        new_query = parse.urlencode(query_params, doseq=True)
        token_endpoint_url_without_signature = parse.urlunparse(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment,
            )
        )

        return token_endpoint_url_without_signature


class MedMijAccessTokenCallbackUrlDirector:
    @inject.autoparams("builder")
    def __init__(self, builder: UrlBuilder) -> None:
        self._builder = builder

    def add_access_code(self, access_code: str) -> None:
        self._builder.add_param(name="access_code", value=access_code)

    def add_token_type(self, type: str) -> None:
        self._builder.add_param(name="token_type", value=type)

    def add_expires_in(self, expires_in: int) -> None:
        self._builder.add_param(name="expires_in", value=str(expires_in))

    def add_refresh_code(self, refresh_code: str) -> None:
        self._builder.add_param(name="refresh_code", value=refresh_code)

    def add_scope(self, scope: str) -> None:
        self._builder.add_param(name="scope", value=scope)

    def add_correlation_id(self, correlation_id: str) -> None:
        self._builder.add_param(name="correlation_id", value=correlation_id)

    def build_url(
        self,
        callback_url: str,
        access_token: str,
        token_type: str,
        expires_in: int,
        refresh_token: str,
        scope: str,
        correlation_id: str,
    ) -> str:
        self.add_access_code(access_code=access_token)
        self.add_token_type(type=token_type)
        self.add_expires_in(expires_in=expires_in)
        self.add_refresh_code(refresh_code=refresh_token)
        self.add_scope(scope=scope)
        self.add_correlation_id(correlation_id=correlation_id)

        return self._builder.build(location=callback_url)


class MedMijOauthTokenService:
    @inject.autoparams()
    def __init__(
        self,
        adapter: OauthTokenAdapter,
        director: MedMijAccessTokenCallbackUrlDirector = resolve_instance(
            MedMijAccessTokenCallbackUrlDirector
        ),
        medmij_logger: MedMijLogger = resolve_instance(MedMijLogger),
        log_message_factory: LogMessageFactory = resolve_instance(LogMessageFactory),
    ) -> None:
        self.__director: MedMijAccessTokenCallbackUrlDirector = director
        self.__adapter: OauthTokenAdapter = adapter
        self.__medmij_logger: MedMijLogger = medmij_logger
        self.__log_message_factory: LogMessageFactory = log_message_factory

    async def retrieve_access_token(
        self,
        token_server_uri: str,
        code: str,
        correlation_id: str,
    ) -> AccessTokenDTO:
        medmij_request_id = self.__create_medmij_request_id()

        self.__medmij_logger.log(
            self.__log_message_factory.send_token_request(
                token_server_uri=token_server_uri,
                method="POST",
                server_id=ServerIdentifier.get_server_id_for_uri(uri=token_server_uri),
                session_id=correlation_id,
                trace_id=medmij_request_id,
                grant_type=GrantType.AUTHORIZATION_CODE,
            )
        )

        access_token = await self.__adapter.get_access_token(
            token_server_uri=token_server_uri,
            code=code,
            correlation_id=correlation_id,
            medmij_request_id=medmij_request_id,
        )

        return access_token

    async def refresh_access_token(
        self,
        token_server_uri: str,
        refresh_token: str,
        correlation_id: str,
    ) -> AccessTokenDTO:
        medmij_request_id = self.__create_medmij_request_id()

        self.__medmij_logger.log(
            self.__log_message_factory.send_token_request(
                token_server_uri=token_server_uri,
                method="POST",
                server_id=ServerIdentifier.get_server_id_for_uri(uri=token_server_uri),
                session_id=correlation_id,
                trace_id=medmij_request_id,
                grant_type=GrantType.REFRESH_TOKEN,
            ),
        )

        refresh_access_token = await self.__adapter.refresh_access_token(
            token_server_uri=token_server_uri,
            refresh_token=refresh_token,
            correlation_id=correlation_id,
            medmij_request_id=medmij_request_id,
        )

        return refresh_access_token

    def create_access_token_retrieval_redirect_url(
        self,
        client_target_url: str,
        access_token_dto: AccessTokenDTO,
        correlation_id: str,
    ) -> str:
        # Create an url including token data as params. This url will be used in a 307 redirect to the
        # client, from which the client will store the token data.
        url: str = self.__director.build_url(
            callback_url=client_target_url,
            access_token=access_token_dto.access_token,
            token_type=access_token_dto.token_type,
            expires_in=access_token_dto.expires_in,
            refresh_token=access_token_dto.refresh_token,
            scope=access_token_dto.scope,
            correlation_id=correlation_id,
        )

        return url

    def __create_medmij_request_id(self) -> str:
        medmij_request_id: str = str(uuid.uuid4())
        return medmij_request_id
