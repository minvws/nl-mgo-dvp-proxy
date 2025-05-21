import inject
import pytest
from fastapi.testclient import TestClient
from httpx import ConnectTimeout, HTTPStatusError, Request, Response
from inject import Binder
from pytest_mock import MockerFixture

from app.authentication.adapters import MedMijOauthTokenAdapter, MockedOauthTokenAdapter
from app.authentication.exceptions import AuthorizationHttpException
from app.authentication.models import AccessTokenDTO
from tests.utils import configure_bindings


class TestMedMijOauthTokenAdapter:
    @pytest.mark.asyncio
    async def test_retrieve_access_token(
        self, test_client: TestClient, mocker: MockerFixture
    ) -> None:
        self.__configure_adapter()
        adapter: MedMijOauthTokenAdapter = inject.instance(MedMijOauthTokenAdapter)

        mock_response: Response = mocker.Mock()
        mocker.patch.object(
            mock_response,
            "json",
            return_value={
                "access_token": "test_access_token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "test_refresh_token",
                "scope": "test_scope",
            },
        )

        mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

        access_token: AccessTokenDTO = await adapter.get_access_token(
            token_server_uri="http://localhost/token",
            code="test_code",
            correlation_id="test_correlation_id",
            medmij_request_id="test_medmij_request_id",
        )

        assert isinstance(access_token, AccessTokenDTO)
        assert access_token.access_token == "test_access_token"
        assert access_token.token_type == "Bearer"
        assert access_token.expires_in == 3600
        assert access_token.refresh_token == "test_refresh_token"
        assert access_token.scope == "test_scope"

    @pytest.mark.asyncio
    async def test_refresh_access_token(
        self, test_client: TestClient, mocker: MockerFixture
    ) -> None:
        self.__configure_adapter()
        adapter: MedMijOauthTokenAdapter = inject.instance(MedMijOauthTokenAdapter)

        mock_response: Response = mocker.Mock()
        mocker.patch.object(
            mock_response,
            "json",
            return_value={
                "access_token": "test_access_token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "test_refresh_token",
                "scope": "test_scope",
            },
        )

        mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

        access_token: AccessTokenDTO = await adapter.refresh_access_token(
            token_server_uri="http://localhost/token",
            refresh_token="test_refresh_token",
            correlation_id="test_correlation_id",
            medmij_request_id="test_medmij_request_id",
        )

        assert isinstance(access_token, AccessTokenDTO)
        assert access_token.access_token == "test_access_token"
        assert access_token.token_type == "Bearer"
        assert access_token.expires_in == 3600
        assert access_token.refresh_token == "test_refresh_token"
        assert access_token.scope == "test_scope"

    @pytest.mark.asyncio
    async def test_retrieve_access_token_fails_with_a_400_error(
        self, test_client: TestClient, mocker: MockerFixture
    ) -> None:
        self.__configure_adapter()
        adapter: MedMijOauthTokenAdapter = inject.instance(MedMijOauthTokenAdapter)

        mock_response = Response(
            status_code=400,
            request=Request("POST", "https://example.com"),
            json={
                "error": "invalid_request",
                "error_description": "The request is missing a required parameter.",
            },
        )

        mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

        with pytest.raises(AuthorizationHttpException):
            await adapter.get_access_token(
                token_server_uri="http://localhost/token",
                code="test_code",
                correlation_id="test_correlation_id",
                medmij_request_id="test_medmij_request_id",
            )

    @pytest.mark.asyncio
    async def test_retrieve_access_token_fails_with_a_405_error(
        self, test_client: TestClient, mocker: MockerFixture
    ) -> None:
        self.__configure_adapter()
        adapter: MedMijOauthTokenAdapter = inject.instance(MedMijOauthTokenAdapter)

        mock_response = Response(
            status_code=405,
            request=Request("POST", "https://example.com"),
            content="Client error '405 Method Not Allowed' for url 'http://localhost:8001/token?grant_type=authorization_code&code=5a21f31d-4a00-4e47-aa97-501d6b296572&client_id=test.mgo.medmij%40denhaag&redirect_uri=http%3A%2F%2Flocalhost%3A8001%2Fauth%2Fcallback'\\nFor more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/405",
        )
        mocker.patch(
            "httpx.AsyncClient.post",
            side_effect=HTTPStatusError(
                "HTTP error occurred",
                request=mock_response.request,
                response=mock_response,
            ),
        )

        with pytest.raises(AuthorizationHttpException) as e:
            await adapter.get_access_token(
                token_server_uri="http://localhost/token",
                code="test_code",
                correlation_id="test_correlation_id",
                medmij_request_id="test_medmij_request_id",
            )
        assert e.value.status_code == 405

    @pytest.mark.asyncio
    async def test_retrieve_access_token_fails_with_a_connect_timout(
        self, test_client: TestClient, mocker: MockerFixture
    ) -> None:
        self.__configure_adapter()
        adapter: MedMijOauthTokenAdapter = inject.instance(MedMijOauthTokenAdapter)

        mocker.patch(
            "httpx.AsyncClient.post", side_effect=ConnectTimeout("Connection timed out")
        )

        with pytest.raises(AuthorizationHttpException) as e:
            await adapter.get_access_token(
                token_server_uri="http://localhost/token",
                code="test_code",
                correlation_id="test_correlation_id",
                medmij_request_id="test_medmij_request_id",
            )
        assert e.value.status_code == 500

    def __configure_adapter(self) -> None:
        adapter: MedMijOauthTokenAdapter = MedMijOauthTokenAdapter(
            client_id="test_client_id",
            redirect_uri="http://localhost/redirect",
        )

        def bindings_override(binder: Binder) -> Binder:
            binder.bind(MedMijOauthTokenAdapter, adapter)
            return binder

        configure_bindings(bindings_override=bindings_override)


class TestMockedOauthTokenAdapter:
    @pytest.fixture
    def adapter(self) -> MockedOauthTokenAdapter:
        return MockedOauthTokenAdapter(client_id="test_client_id")

    @pytest.mark.asyncio
    async def test_retrieve_access_token(
        self, adapter: MockedOauthTokenAdapter
    ) -> None:
        result: AccessTokenDTO = await adapter.get_access_token(
            token_server_uri="http://test.com",
            code="test_code",
            correlation_id="test_correlation_id",
            medmij_request_id="test_medmij_request_id",
        )
        assert isinstance(result, AccessTokenDTO)
        assert result.access_token == "mocked_access_token"
        assert result.refresh_token == "mocked_refresh_token"
        assert result.token_type == "Bearer"
        assert result.expires_in == 900
        assert result.scope == "48 49"

    @pytest.mark.asyncio
    async def test_refresh_access_token(self, adapter: MockedOauthTokenAdapter) -> None:
        result: AccessTokenDTO = await adapter.refresh_access_token(
            token_server_uri="http://test.com",
            refresh_token="mocked_refresh_token",
            correlation_id="test_correlation_id",
            medmij_request_id="test_medmij_request_id",
        )
        assert isinstance(result, AccessTokenDTO)
        assert result.access_token == "mocked_access_token"
        assert result.refresh_token == "mocked_refresh_token"
        assert result.token_type == "Bearer"
        assert result.expires_in == 900
        assert result.scope == "48 49"
