import base64
import os
import time
import uuid
from urllib.parse import quote

import faker
import inject
import pytest
from fastapi.testclient import TestClient
from inject import ConstructorTypeError
from pytest_mock import MockerFixture

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
    def state_service(self) -> StateService:
        key: bytes = self.__get_random_key()
        return StateService(signing_keys=[key], signature_lifetime_secs=900)

    def __get_random_key(self) -> bytes:
        key = os.urandom(32)
        key = base64.urlsafe_b64encode(key)
        return key

    @pytest.fixture
    def state_dto(self) -> StateDTO:
        return StateDTO(
            client_target_url="https://example.com",
            token_endpoint_url="https://example.com/token",
            correlation_id="correlation_id",
        )

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
        self, state_service: StateService, state_dto: StateDTO
    ) -> None:
        token = state_service.generate_state_token(state_dto)

        assert token is not None
        # Token should not be empty
        assert len(token) >= 128
        # Token should not be too long
        assert len(token) < 512

    def test_it_can_decrypt_a_state_token(
        self, state_service: StateService, state_dto: StateDTO
    ) -> None:
        token = state_service.generate_state_token(state_dto)
        decrypted_token: StateDTO = state_service.decrypt_state_token(token)

        assert decrypted_token.client_target_url == state_dto.client_target_url

    def test_it_can_verify_a_state_token_without_exception(
        self, state_service: StateService, state_dto: StateDTO
    ) -> None:
        token = state_service.generate_state_token(state_dto)
        state_service.verify_state_token(token)

    def test_the_state_token_includes_a_lifetime(
        self, state_service: StateService, state_dto: StateDTO
    ) -> None:
        now = int(time.time())
        exp = now + 900

        token = state_service.generate_state_token(state_dto)

        decrypted_token: StateDTO = state_service.decrypt_state_token(token)

        assert decrypted_token.expiration_time == exp

    def test_the_state_token_includes_a_correlation_id(
        self,
        state_service: StateService,
        mocker: MockerFixture,
        state_dto: StateDTO,
    ) -> None:
        token: str = state_service.generate_state_token(state_dto=state_dto)
        decrypted_token: StateDTO = state_service.decrypt_state_token(token=token)

        assert decrypted_token.correlation_id == "correlation_id"

    def test_the_token_is_invalid_after_expiry(
        self,
        state_service: StateService,
        state_dto: StateDTO,
        mocker: MockerFixture,
    ) -> None:
        mocker.patch("time.time", return_value=0)
        token = state_service.generate_state_token(state_dto=state_dto)
        mocker.patch("time.time", return_value=901)

        with pytest.raises(ExpiredStateException, match="State token has expired") as e:
            state_service.decrypt_state_token(token)

    def test_it_throws_an_exception_when_exp_is_not_int(
        self,
        state_service: StateService,
        state_dto: StateDTO,
        mocker: MockerFixture,
    ) -> None:
        mocker.patch("json.dumps", return_value='{"expiration_time": "not an int"}')
        token = state_service.generate_state_token(state_dto)

        with pytest.raises(
            ExpirationTimeTypeException, match="Expiration time is not an integer"
        ) as e:
            state_service.decrypt_state_token(token)

    def test_it_throws_an_exception_when_no_exp_is_found(
        self,
        state_service: StateService,
        state_dto: StateDTO,
        mocker: MockerFixture,
    ) -> None:
        mocker.patch("json.dumps", return_value="{}")
        token = state_service.generate_state_token(state_dto)

        with pytest.raises(
            ExpirationTimeMissingException,
            match="No expiration time found in State token",
        ) as e:
            state_service.decrypt_state_token(token)

    def test_it_throws_an_exception_when_exp_is_none(
        self,
        state_service: StateService,
        state_dto: StateDTO,
        mocker: MockerFixture,
    ) -> None:
        mocker.patch("json.dumps", return_value='{"exp": null}')
        token = state_service.generate_state_token(state_dto)

        with pytest.raises(
            ExpirationTimeMissingException,
            match="No expiration time found in State token",
        ) as e:
            state_service.decrypt_state_token(token)

    def test_it_throws_an_exception_when_it_cannot_decrypt_the_token_with_any_key(
        self,
        state_service: StateService,
        state_dto: StateDTO,
        mocker: MockerFixture,
    ) -> None:
        token = state_service.generate_state_token(state_dto)

        key: bytes = self.__get_random_key()
        new_state_service = StateService(
            signing_keys=[key], signature_lifetime_secs=900
        )

        with pytest.raises(InvalidStateException, match="Could not decrypt state") as e:
            new_state_service.decrypt_state_token(token)


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
        encoded_redirect_uri: str = quote(string=redirect_uri)
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

    def test_it_pops_the_mgo_signature_from_the_token_url(
        self, mocker: MockerFixture
    ) -> None:
        mock_state_service = mocker.Mock(StateService)
        director_instance = MedMijAuthRequestUrlDirector(
            client_id="test",
            redirect_url="https://example.com/callback",
            builder=UrlBuilder(),
            state_service=mock_state_service,
        )

        token_url = "https://example-token-server.com?mgo_signature=signature&foo=bar"

        director_instance.add_state(
            client_target_url="https://example.com",
            correlation_id=uuid.uuid4(),
            token_endpoint_url=token_url,
        )

        mock_state_service.generate_state_token.assert_called_once()
        args, kwargs = mock_state_service.generate_state_token.call_args
        assert (
            kwargs["state_dto"].token_endpoint_url
            == "https://example-token-server.com?foo=bar"
        )


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
