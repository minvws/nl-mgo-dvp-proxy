from base64 import urlsafe_b64encode
from logging import Logger
from typing import Any

from faker import Faker
from fastapi import HTTPException
from pytest import fixture, raises
from pydantic_core import Url
from pytest_mock import MockerFixture, MockType
from requests import RequestException, Response

from app.config.models import VadHttpClientConfig
from app.oidc.clients import VadHttpClient
from app.oidc.schemas import TokenGrantType
from app.security.services import SslContextFactory


class TestVadHttpClient:
    @fixture
    def mock_config(self, mocker: MockerFixture, faker: Faker) -> MockType:
        mock_config: MockType = mocker.Mock(spec=VadHttpClientConfig)
        mock_config.url = Url(f"https://{faker.domain_name()}:{faker.random_int()}")
        mock_config.client_cert = None
        mock_config.client_key = None
        mock_config.ca_cert = None
        return mock_config

    @fixture
    def mock_logger(self, mocker: MockerFixture) -> MockType:
        mock: MockType = mocker.Mock(spec=Logger)
        return mock

    @fixture
    def mock_requests_get(self, mocker: MockerFixture) -> Any:
        return mocker.patch("app.oidc.clients.get")

    @fixture
    def mock_requests_post(self, mocker: MockerFixture) -> Any:
        return mocker.patch("app.oidc.clients.post")

    @fixture
    def client(
        self, mock_config: VadHttpClientConfig, mock_logger: Logger
    ) -> VadHttpClient:
        client: VadHttpClient = VadHttpClient(
            config=mock_config,
            logger=mock_logger,
            ssl_context=SslContextFactory.create(
                ca_cert=mock_config.ca_cert,
                client_cert=mock_config.client_cert,
                client_key=mock_config.client_key,
            ),
        )
        return client

    def test_gets_oidc_config_via_http(
        self,
        client: VadHttpClient,
        mock_config: VadHttpClientConfig,
        mock_requests_get: MockType,
    ) -> None:
        client.get_oidc_config()

        mock_requests_get.assert_called_once_with(
            f"{mock_config.url}/.well-known/openid-configuration",
            timeout=5,
            verify=False,
        )

    def test_posts_authorization_code_via_http_without_client_assertion(
        self,
        client: VadHttpClient,
        mock_config: VadHttpClientConfig,
        mock_requests_post: MockType,
        faker: Faker,
    ) -> None:
        endpoint = faker.uri_path()
        grant_type = faker.random_element(elements=TokenGrantType)
        authz_code = str(faker.sha256(raw_output=True))
        redirect_uri = faker.uri()
        code_verifier = str(faker.sha256(raw_output=True))
        client_id = str(faker.uuid4())

        mock_requests_post.return_value.json.return_value = {
            "access_token": faker.sha256(),
            "token_type": faker.random_element(elements=["Bearer"]),
            "expires_in": faker.random_int(),
        }

        client.post_authz_code(
            endpoint,
            grant_type,
            authz_code,
            redirect_uri,
            code_verifier,
            client_id,
        )

        mock_requests_post.assert_called_once_with(
            f"{mock_config.url}{endpoint}",
            data={
                "grant_type": grant_type,
                "code": authz_code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
                "client_id": client_id,
            },
            timeout=5,
            verify=False,
        )

    def test_posts_authorization_code_via_http_with_client_assertion(
        self,
        client: VadHttpClient,
        mock_config: VadHttpClientConfig,
        mock_requests_post: MockType,
        faker: Faker,
    ) -> None:
        endpoint = faker.uri_path()
        grant_type = faker.random_element(elements=TokenGrantType)
        authz_code = str(faker.sha256(raw_output=True))
        redirect_uri = faker.uri()
        code_verifier = str(faker.sha256(raw_output=True))
        client_id = str(faker.uuid4())
        client_assertion_type = faker.uri()
        client_assertion = self.__generate_fake_jwt(faker=faker)

        mock_requests_post.return_value.json.return_value = {
            "access_token": faker.sha256(),
            "token_type": faker.random_element(elements=["Bearer"]),
            "expires_in": faker.random_int(),
        }

        client.post_authz_code(
            endpoint,
            grant_type,
            authz_code,
            redirect_uri,
            code_verifier,
            client_id,
            client_assertion_type,
            client_assertion,
        )

        mock_requests_post.assert_called_once_with(
            f"{mock_config.url}{endpoint}",
            data={
                "grant_type": grant_type,
                "code": authz_code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
                "client_id": client_id,
                "client_assertion_type": client_assertion_type,
                "client_assertion": client_assertion,
            },
            timeout=5,
            verify=False,
        )

    def test_gets_userinfo_via_http(
        self,
        client: VadHttpClient,
        mock_config: VadHttpClientConfig,
        mock_requests_get: MockType,
        faker: Faker,
    ) -> None:
        endpoint = faker.uri_path()
        access_token = str(faker.sha256(raw_output=True))

        client.get_userinfo(endpoint=endpoint, access_token=access_token)

        mock_requests_get.assert_called_once_with(
            f"{mock_config.url}{endpoint}",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=5,
            verify=False,
        )

    def test_make_web_request_handles_error_response(
        self,
        client: VadHttpClient,
        mock_logger: MockType,
        mock_requests_get: MockType,
        faker: Faker,
    ) -> None:
        url = faker.uri()
        status_code = faker.random_int(min=400, max=599)
        error_message = faker.sentence(nb_words=5)
        error_response = Response()
        error_response.status_code = status_code
        error_response.reason = error_message
        error_response.url = url

        mock_requests_get.return_value = error_response

        with raises(HTTPException, match="VAD Bad Request") as exc_info:
            client.get_oidc_config()

        assert exc_info.value.status_code == 502
        mock_logger.error.assert_called_once_with(
            "VAD Bad Request: %s",
            f"{status_code} Client Error: {error_message} for url: {url}",
        )

    def test_make_web_request_handles_request_exception(
        self, client: VadHttpClient, mock_logger: MockType, mock_requests_get: MockType
    ) -> None:
        error_message = "Some unexpected error"

        mock_requests_get.side_effect = RequestException(error_message)

        with raises(HTTPException, match="VAD Bad Request") as exc_info:
            client.get_oidc_config()

        assert exc_info.value.status_code == 502
        mock_logger.error.assert_called_once_with(
            "VAD Bad Request: %s",
            error_message,
        )

    def test_make_web_request_does_not_include_previously_passed_request_kwargs(
        self,
        client: VadHttpClient,
        mock_config: VadHttpClientConfig,
        mock_requests_get: MockType,
        mock_requests_post: MockType,
        faker: Faker,
    ) -> None:
        token_endpoint = faker.uri_path()
        userinfo_endpoint = faker.uri_path()
        grant_type = faker.random_element(elements=TokenGrantType)
        authz_code = str(faker.sha256(raw_output=True))
        redirect_uri = faker.uri()
        code_verifier = str(faker.sha256(raw_output=True))
        client_id = str(faker.uuid4())
        client_assertion_type = faker.uri()
        client_assertion = self.__generate_fake_jwt(faker=faker)
        access_token = str(faker.sha256(raw_output=True))

        mock_requests_post.return_value.json.return_value = {
            "access_token": faker.sha256(),
            "token_type": faker.random_element(elements=["Bearer"]),
            "expires_in": faker.random_int(),
        }

        client.post_authz_code(
            token_endpoint,
            grant_type,
            authz_code,
            redirect_uri,
            code_verifier,
            client_id,
            client_assertion_type,
            client_assertion,
        )
        client.get_userinfo(endpoint=userinfo_endpoint, access_token=access_token)

        mock_requests_post.assert_called_once_with(
            f"{mock_config.url}{token_endpoint}",
            data={
                "grant_type": grant_type,
                "code": authz_code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
                "client_id": client_id,
                "client_assertion_type": client_assertion_type,
                "client_assertion": client_assertion,
            },
            timeout=5,
            verify=False,
        )

        mock_requests_get.assert_called_once_with(
            f"{mock_config.url}{userinfo_endpoint}",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=5,
            verify=False,
        )

    def __generate_fake_jwt(self, faker: Faker) -> str:
        header = urlsafe_b64encode(faker.binary(10)).decode()
        payload = urlsafe_b64encode(faker.binary(20)).decode()
        signature = urlsafe_b64encode(faker.binary(30)).decode()

        return f"{header}.{payload}.{signature}"
