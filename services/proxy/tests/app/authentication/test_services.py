import base64
import os
import time
import uuid

import faker
import inject
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from inject import ConstructorTypeError
from pytest_mock import MockerFixture

from app.authentication.constants import STATE_TOKEN_SEPARATOR
from app.authentication.exceptions import (
    ExpirationTimeMissingException,
    ExpirationTimeTypeException,
    ExpiredStateException,
    InvalidStateException,
)
from app.authentication.models import AccessTokenDTO, StateDTO
from app.authentication.services import (
    MedMijAccessTokenCallbackUrlDirector,
    MedMijAuthRequestUrlDirector,
    MedMijOauthTokenService,
    StateService,
    UrlBuilder,
)


class TestStateService:
    @pytest.fixture
    def state_signing_key(self) -> bytes:
        return self.__get_random_key()

    @pytest.fixture
    def state_service(self, state_signing_key: bytes) -> StateService:
        return StateService(
            signing_keys=[state_signing_key], signature_lifetime_secs=900
        )

    def __get_random_key(self) -> bytes:
        key = os.urandom(32)
        key = base64.urlsafe_b64encode(key)
        return key

    def __encrypt_state_payload(self, signing_key: bytes, payload: str) -> str:
        return Fernet(signing_key).encrypt(payload.encode()).decode("utf-8")

    @pytest.fixture
    def generate_state_token_args(self, faker: faker.Faker) -> dict[str, str]:
        return {
            "correlation_id": faker.uuid4(),
            "token_endpoint_url": faker.url(),
            "client_target_url": faker.url(),
        }

    def test_it_throws_error_when_no_key_is_provided(self) -> None:
        try:
            StateService()  # type: ignore
            assert False
        except TypeError:
            assert True

    def test_it_depends_on_the_signature_lifetime(self) -> None:
        with pytest.raises(Exception) as e:
            StateService(b"")  # type: ignore
        assert (
            "missing 1 required positional argument: 'signature_lifetime_secs'"
            in str(e.value)
        )

    def test_it_can_generate_a_state_token(
        self, state_service: StateService, generate_state_token_args: dict[str, str]
    ) -> None:
        token = state_service.generate_state_token(**generate_state_token_args)

        assert token is not None
        # Token should not be empty
        assert len(token) >= 128
        # Token should not be too long
        assert len(token) < 512

    def test_it_keeps_a_longer_state_token_within_the_size_limit(
        self, state_service: StateService, generate_state_token_args: dict[str, str]
    ) -> None:
        state_dto = StateDTO(
            correlation_id="123e4567-e89b-12d3-a456-426614174000",
            token_endpoint_url=(
                "https://authorization-server.example.com/oauth2/token/tenant/region/"
                "environment/node?client=medmij&flow=collect&version=v1"
            ),
            client_target_url=(
                "https://mgo.example.com/callback/mobile/native/session/redirect/"
                "proxy?platform=ios&return=dashboard&context=collect&tenant=prod"
            ),
            expiration_time=9999999999,
        )

        token = state_service.generate_state_token(**generate_state_token_args)

        assert len(token) < 512

    def test_it_can_decrypt_a_state_token(
        self, state_service: StateService, generate_state_token_args: dict[str, str]
    ) -> None:
        token = state_service.generate_state_token(**generate_state_token_args)
        decrypted_token: StateDTO = state_service.get_state_dto(token)

        assert (
            decrypted_token.client_target_url
            == generate_state_token_args["client_target_url"]
        )

    def test_it_can_verify_a_state_token_without_exception(
        self, state_service: StateService, generate_state_token_args: dict[str, str]
    ) -> None:
        token = state_service.generate_state_token(**generate_state_token_args)
        state_service.verify_state_token(token)

    def test_the_state_token_includes_a_lifetime(
        self, state_service: StateService, generate_state_token_args: dict[str, str]
    ) -> None:
        now = int(time.time())
        exp = now + 900

        token = state_service.generate_state_token(**generate_state_token_args)

        decrypted_token: StateDTO = state_service.get_state_dto(token)

        assert decrypted_token.expiration_time == exp

    def test_the_state_token_includes_a_correlation_id(
        self,
        state_service: StateService,
        mocker: MockerFixture,
        generate_state_token_args: dict[str, str],
    ) -> None:
        token: str = state_service.generate_state_token(**generate_state_token_args)
        decrypted_token: StateDTO = state_service.get_state_dto(token=token)

        assert (
            decrypted_token.correlation_id
            == generate_state_token_args["correlation_id"]
        )

    def test_the_token_is_invalid_after_expiry(
        self,
        state_service: StateService,
        generate_state_token_args: dict[str, str],
        mocker: MockerFixture,
    ) -> None:
        mocker.patch("time.time", return_value=0)
        token = state_service.generate_state_token(**generate_state_token_args)
        mocker.patch("time.time", return_value=901)

        with pytest.raises(ExpiredStateException, match="State token has expired") as e:
            state_service.get_state_dto(token)

    def test_it_throws_an_exception_when_exp_is_not_int(
        self,
        state_signing_key: bytes,
        state_service: StateService,
    ) -> None:
        token = self.__encrypt_state_payload(
            state_signing_key,
            STATE_TOKEN_SEPARATOR.join(
                [
                    "correlation_id",
                    "https://example.com/token",
                    "https://example.com/callback",
                    "not an int",
                ]
            ),
        )

        with pytest.raises(
            ExpirationTimeTypeException, match="Expiration time is not an integer"
        ) as e:
            state_service.get_state_dto(token)

    def test_it_throws_an_exception_when_no_exp_is_found(
        self,
        state_signing_key: bytes,
        state_service: StateService,
    ) -> None:
        token = self.__encrypt_state_payload(
            state_signing_key,
            STATE_TOKEN_SEPARATOR.join(
                [
                    "correlation_id",
                    "https://example.com/token",
                    "https://example.com/callback",
                ]
            ),
        )

        with pytest.raises(
            InvalidStateException,
            match="Expected 4 parts in deserialized state, got: 3",
        ) as e:
            state_service.get_state_dto(token)

    def test_it_throws_an_exception_when_exp_is_none(
        self,
        state_signing_key: bytes,
        state_service: StateService,
    ) -> None:
        token = self.__encrypt_state_payload(
            state_signing_key,
            STATE_TOKEN_SEPARATOR.join(
                [
                    "correlation_id",
                    "https://example.com/token",
                    "https://example.com/callback",
                    "",
                ]
            ),
        )

        with pytest.raises(
            ExpirationTimeMissingException,
            match="No expiration time found in State token",
        ) as e:
            state_service.get_state_dto(token)

    def test_it_throws_an_exception_when_state_payload_has_too_many_parts(
        self,
        state_signing_key: bytes,
        state_service: StateService,
    ) -> None:
        token = self.__encrypt_state_payload(
            state_signing_key,
            STATE_TOKEN_SEPARATOR.join(
                [
                    "correlation_id",
                    "https://example.com/token",
                    "https://example.com/callback",
                    "123",
                    "unexpected",
                ]
            ),
        )

        with pytest.raises(
            InvalidStateException,
            match="Expected 4 parts in deserialized state, got: 5",
        ):
            state_service.get_state_dto(token)

    def test_it_throws_an_exception_when_it_cannot_decrypt_the_token_with_any_key(
        self,
        state_service: StateService,
        generate_state_token_args: dict[str, str],
    ) -> None:
        token = state_service.generate_state_token(**generate_state_token_args)

        key: bytes = self.__get_random_key()
        new_state_service = StateService(
            signing_keys=[key], signature_lifetime_secs=900
        )

        with pytest.raises(InvalidStateException, match="Could not decrypt state") as e:
            new_state_service.get_state_dto(token)

    def test_it_can_decrypt_the_token_with_a_secondary_key(
        self, state_signing_key: bytes, generate_state_token_args: dict[str, str]
    ) -> None:
        secondary_key = self.__get_random_key()
        token = StateService(
            signing_keys=[secondary_key], signature_lifetime_secs=900
        ).generate_state_token(**generate_state_token_args)

        state_service = StateService(
            signing_keys=[state_signing_key, secondary_key],
            signature_lifetime_secs=900,
        )

        decrypted_token = state_service.get_state_dto(token)

        assert (
            decrypted_token.client_target_url
            == generate_state_token_args["client_target_url"]
        )


class TestMedMijAuthRequestUrlDirector:
    @pytest.fixture
    def create_medmij_oauth_url_director(
        self, mocker: MockerFixture
    ) -> MedMijAuthRequestUrlDirector:
        state_service_mock = mocker.Mock(StateService)
        state_service_mock.generate_state_token.return_value = "secret"

        director: MedMijAuthRequestUrlDirector = MedMijAuthRequestUrlDirector(
            builder=UrlBuilder(),
            state_service=state_service_mock,
            client_id="mgo.medmij@mgo.nl",
            redirect_url="https://example.com/callback",
        )

        return director

    def test_it_adds_state_parameter_to_parameters(
        self, create_medmij_oauth_url_director: MedMijAuthRequestUrlDirector
    ) -> None:
        director: MedMijAuthRequestUrlDirector = create_medmij_oauth_url_director
        test_url = "https://client.example.com/callback"
        token_endpoint_url = "https://example.com/token"

        director.add_state(
            correlation_id=str(uuid.uuid4()),
            token_endpoint_url=token_endpoint_url,
            client_target_url=test_url,
        )
        test_scope = faker.Faker().word()
        url: str = director.build_authorization_request_url(
            authorization_server_url=test_url,
            token_endpoint_url=token_endpoint_url,
            client_target_url="https://client.example.com/callback",
            scope=test_scope,
        )

        assert "?state=secret" in url

    def test_it_appends_state_parameter_to_parameters_when_url_contains_query_params(
        self,
        mocker: MockerFixture,
        create_medmij_oauth_url_director: MedMijAuthRequestUrlDirector,
    ) -> None:
        director: MedMijAuthRequestUrlDirector = create_medmij_oauth_url_director
        test_url = "https://example.com?query=param"
        token_endpoint_url = "https://example.com/token"

        director.add_state(
            str(uuid.uuid4()),
            token_endpoint_url=token_endpoint_url,
            client_target_url=test_url,
        )

        test_scope = faker.Faker().word()
        url: str = director.build_authorization_request_url(
            authorization_server_url=test_url,
            token_endpoint_url=token_endpoint_url,
            client_target_url="https://client.example.com/callback",
            scope=test_scope,
        )
        assert "&state=secret" in url

    def test_it_adds_correlation_id_to_parameters(
        self, create_medmij_oauth_url_director: MedMijAuthRequestUrlDirector
    ) -> None:
        director: MedMijAuthRequestUrlDirector = create_medmij_oauth_url_director
        test_url = "https://example.com"
        token_endpoint_url = "https://example.com/token"

        director.add_correlation_id(str(uuid.uuid4()))
        test_scope = faker.Faker().word()
        url: str = director.build_authorization_request_url(
            authorization_server_url=test_url,
            token_endpoint_url=token_endpoint_url,
            client_target_url="https://client.example.com/callback",
            scope=test_scope,
        )

        assert "X-Correlation-ID=" in url

    def test_it_adds_medmij_id_to_parameters(
        self, create_medmij_oauth_url_director: MedMijAuthRequestUrlDirector
    ) -> None:
        director: MedMijAuthRequestUrlDirector = create_medmij_oauth_url_director
        test_url = "https://example.com"
        token_endpoint_url = "https://example.com/token"

        director.add_medmij_id()
        test_scope = faker.Faker().word()
        url: str = director.build_authorization_request_url(
            authorization_server_url=test_url,
            token_endpoint_url=token_endpoint_url,
            client_target_url="https://client.example.com/callback",
            scope=test_scope,
        )
        assert "MedMij-Request-ID=" in url

    def test_it_adds_the_client_id_to_parameters(
        self, create_medmij_oauth_url_director: MedMijAuthRequestUrlDirector
    ) -> None:
        director: MedMijAuthRequestUrlDirector = create_medmij_oauth_url_director
        test_url = "https://example.com"
        token_endpoint_url = "https://example.com/token"

        director.add_client_id()
        test_scope = faker.Faker().word()
        url: str = director.build_authorization_request_url(
            authorization_server_url=test_url,
            token_endpoint_url=token_endpoint_url,
            client_target_url="https://client.example.com/callback",
            scope=test_scope,
        )

        assert "client_id=mgo.medmij@mgo.nl" in url

    def test_it_adds_the_response_type_parameter(
        self, create_medmij_oauth_url_director: MedMijAuthRequestUrlDirector
    ) -> None:
        director: MedMijAuthRequestUrlDirector = create_medmij_oauth_url_director
        test_url = "https://example.com"
        token_endpoint_url = "https://example.com/token"

        director.add_response_type()
        test_scope = faker.Faker().word()
        url: str = director.build_authorization_request_url(
            authorization_server_url=test_url,
            token_endpoint_url=token_endpoint_url,
            client_target_url="https://client.example.com/callback",
            scope=test_scope,
        )

        assert "response_type=code" in url

    def test_it_depends_on_a_client_id(self, mocker: MockerFixture) -> None:
        with pytest.raises(ConstructorTypeError) as e:
            state_service_mock = mocker.Mock(StateService)
            state_service_mock.generate_state_token.return_value = "secret"

            director = MedMijAuthRequestUrlDirector(
                builder=UrlBuilder(),
                state_service=state_service_mock,
                redirect_url="https://example.com/callback",
            )

        assert "missing 1 required positional argument: 'client_id'" in str(e.value)

    def test_it_depends_on_a_redirect_url(self, mocker: MockerFixture) -> None:
        with pytest.raises(ConstructorTypeError) as e:
            state_service_mock = mocker.Mock(StateService)
            state_service_mock.generate_state_token.return_value = "secret"

            director = MedMijAuthRequestUrlDirector(
                builder=UrlBuilder(),
                state_service=state_service_mock,
                client_id="client_id",
            )
            assert "missing 1 required positional argument: 'redirect_url'" in str(
                e.value
            )

    def test_it_adds_the_encoded_redirect_uri_parameter(
        self, create_medmij_oauth_url_director: MedMijAuthRequestUrlDirector
    ) -> None:
        director: MedMijAuthRequestUrlDirector = create_medmij_oauth_url_director
        test_url = "https://example.com"
        redirect_uri = "https://example.com/callback"
        encoded_redirect_uri: str = "https%3A%2F%2Fexample.com%2Fcallback"
        token_endpoint_url = "https://example.com/token"

        director.add_redirect_uri()
        test_scope = faker.Faker().word()
        url: str = director.build_authorization_request_url(
            authorization_server_url=test_url,
            token_endpoint_url=token_endpoint_url,
            client_target_url="https://client.example.com/callback",
            scope=test_scope,
        )

        assert encoded_redirect_uri in url

    def test_it_adds_the_zorgaanbieder_id_scope_parameter(
        self, create_medmij_oauth_url_director: MedMijAuthRequestUrlDirector
    ) -> None:
        director: MedMijAuthRequestUrlDirector = create_medmij_oauth_url_director
        test_url = "https://example.com"
        generator = faker.Faker()
        zorgaanbieder_id: str = generator.word()
        token_endpoint_url = "https://example.com/token"

        director.add_scope(scope=zorgaanbieder_id)
        test_scope = faker.Faker().word()
        url: str = director.build_authorization_request_url(
            authorization_server_url=test_url,
            token_endpoint_url=token_endpoint_url,
            client_target_url="https://client.example.com/callback",
            scope=test_scope,
        )

        assert f"scope={test_scope}" in url

    def test_it_calls_all_director_methods(self, mocker: MockerFixture) -> None:
        state_service_mock = mocker.Mock(StateService)
        state_service_mock.generate_state_token.return_value = "secret"

        director = MedMijAuthRequestUrlDirector(
            builder=UrlBuilder(),
            state_service=state_service_mock,
            client_id="mgo.medmij@mgo.nl",
            redirect_url="https://example.com/callback",
        )

        # Spy on the methods of MedMijAuthRequestUrlDirector
        mocker.spy(director, "add_state")
        mocker.spy(director, "add_client_id")
        mocker.spy(director, "add_correlation_id")
        mocker.spy(director, "add_medmij_id")
        mocker.spy(director, "add_response_type")
        mocker.spy(director, "add_redirect_uri")
        mocker.spy(director, "add_scope")

        test_scope = faker.Faker().word()
        director.build_authorization_request_url(
            authorization_server_url="https://example.com",
            token_endpoint_url="https://example.com/token",
            client_target_url="https://client.example.com/callback",
            scope=test_scope,
        )

        director.add_state.assert_called_once()
        director.add_client_id.assert_called_once()
        director.add_correlation_id.assert_called_once()
        director.add_medmij_id.assert_called_once()
        director.add_response_type.assert_called_once()
        director.add_redirect_uri.assert_called_once()
        director.add_scope.assert_called_once_with(scope=test_scope)


class TestMedMijAccessTokenCallbackUrlBuilder:
    def test_build_url(self) -> None:
        director_instance = MedMijAccessTokenCallbackUrlDirector(builder=UrlBuilder())

        callback_url = "http://example.com/callback"
        access_token = "test_access_token"
        token_type = "Bearer"
        expires_in = 3600
        refresh_token = "test_refresh_token"
        scope = "read write"
        correlation_id = "some_correlation_id"

        expected_url: str = (
            f"{callback_url}?"
            f"access_code={access_token}&"
            f"token_type={token_type}&"
            f"expires_in={expires_in}&"
            f"refresh_code={refresh_token}&"
            f"scope={scope}&"
            f"correlation_id={correlation_id}"
        )

        result_url = director_instance.build_url(
            callback_url=callback_url,
            access_token=access_token,
            token_type=token_type,
            expires_in=expires_in,
            refresh_token=refresh_token,
            scope=scope,
            correlation_id=correlation_id,
        )

        assert result_url == expected_url


class TestMedMijOauthTokenService:
    @pytest.mark.asyncio
    async def test_refresh_access_token(self, test_client: TestClient) -> None:
        service: MedMijOauthTokenService = inject.instance(MedMijOauthTokenService)

        token_server_uri = "https://example.com/token"
        refresh_token = "mocked_refresh_token"
        correlation_id = "mocked_correlation_id"

        result: AccessTokenDTO = await service.refresh_access_token(
            token_server_uri, refresh_token, correlation_id
        )

        assert result.access_token == "mocked_access_token"

    @pytest.mark.asyncio
    async def test_get_access_token(self, test_client: TestClient) -> None:
        service: MedMijOauthTokenService = inject.instance(MedMijOauthTokenService)

        token_server_uri = "https://example.com/token"
        code = "mocked_code"
        correlation_id = "mocked_correlation_id"

        result: AccessTokenDTO = await service.retrieve_access_token(
            token_server_uri, code, correlation_id
        )

        assert result.refresh_token == "mocked_refresh_token"
