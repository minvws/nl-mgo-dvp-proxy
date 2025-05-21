from json import dumps as json_encode
from typing import Any

from faker import Faker
from pytest import fixture
from pytest_mock import MockerFixture, MockType

from app.oidc.clients import VadHttpClient
from app.oidc.repositories import WellKnownVadOidcConfigRepository
from app.oidc.schemas import VadOidcConfiguration


class TestWellKnownVadOidcConfigRepository:
    @fixture
    def mocks(
        self, mocker: MockerFixture
    ) -> tuple[WellKnownVadOidcConfigRepository, MockType]:
        mock_vad_http_client = mocker.Mock(spec=VadHttpClient)
        repository = WellKnownVadOidcConfigRepository(
            vad_http_client=mock_vad_http_client
        )

        return (repository, mock_vad_http_client)

    def test_gets_oidc_configuration_via_vad_http_client(
        self, mocker: MockerFixture, faker: Faker
    ) -> None:
        mock_vad_http_client = mocker.Mock(spec=VadHttpClient)
        repository = WellKnownVadOidcConfigRepository(
            vad_http_client=mock_vad_http_client
        )
        oidc_config = self.__generate_oidc_config_dict(faker)

        mock_vad_http_client.get_oidc_config.return_value.text = json_encode(
            oidc_config
        )

        vad_oidc_configuration = repository.get_all()

        mock_vad_http_client.get_oidc_config.assert_called_once()
        assert vad_oidc_configuration.model_dump() == oidc_config

    def test_gets_oidc_configuration_from_local_cache(
        self, mocker: MockerFixture, faker: Faker
    ) -> None:
        mock_vad_http_client = mocker.Mock(spec=VadHttpClient)
        repository = WellKnownVadOidcConfigRepository(
            vad_http_client=mock_vad_http_client
        )

        cached_vad_oidc_configuration = VadOidcConfiguration(
            **self.__generate_oidc_config_dict(faker)
        )
        repository._WellKnownVadOidcConfigRepository__vad_oidc_config = (
            cached_vad_oidc_configuration
        )

        vad_oidc_configuration = repository.get_all()

        mock_vad_http_client.get_oidc_config.assert_not_called()
        assert vad_oidc_configuration == cached_vad_oidc_configuration

    def __generate_oidc_config_dict(self, faker: Faker) -> dict[str, Any]:
        return {
            "issuer": faker.uri(),
            "authorization_endpoint": faker.uri(),
            "token_endpoint": faker.uri(),
            "scopes_supported": [faker.word()],
            "response_types_supported": [faker.word()],
            "response_modes_supported": [faker.word()],
            "grant_types_supported": [faker.word()],
            "subject_types_supported": [faker.word()],
            "token_endpoint_auth_methods_supported": [faker.word()],
            "claims_parameter_supported": faker.boolean(),
            "userinfo_endpoint": faker.uri(),
        }
