import pytest
from fastapi.testclient import TestClient
from httpx import ConnectTimeout, Request, Response
from inject import Binder
from pytest_mock import MockerFixture

from app.authentication.adapters import MedMijOauthTokenAdapter, MockedOauthTokenAdapter
from app.authentication.exceptions import AuthorizationHttpException
from app.authentication.models import AccessTokenDTO, AsyncOAuthClient
from tests.utils import configure_bindings

ACCESS_TOKEN: str = "access-token"
TOKEN_TYPE: str = "Bearer"
EXPIRES_IN: int = 3600
REFRESH_TOKEN: str = "refresh-token"
SCOPE: str = "read write"


@pytest.fixture
def make_token_response() -> dict[str, str | int]:
    return {
        "access_token": ACCESS_TOKEN,
        "token_type": TOKEN_TYPE,
        "expires_in": EXPIRES_IN,
        "refresh_token": REFRESH_TOKEN,
        "scope": SCOPE,
    }


@pytest.fixture
def mock_response(
    mocker: MockerFixture, make_token_response: dict[str, str | int]
) -> Response:
    mock_response: Response = mocker.Mock()
    mock_response.json.return_value = make_token_response  # type: ignore[attr-defined]

    return mock_response


@pytest.fixture
def mock_client(mocker: MockerFixture) -> AsyncOAuthClient:
    mock_client: AsyncOAuthClient = mocker.AsyncMock(spec=AsyncOAuthClient)
    return mock_client


@pytest.fixture
def token_adapter_mock(
    mock_client: AsyncOAuthClient,
    mock_response: Response,
    mocker: MockerFixture,
) -> MedMijOauthTokenAdapter:
    mock_client.post.return_value = mock_response  # type: ignore[attr-defined]

    adapter: MedMijOauthTokenAdapter = MedMijOauthTokenAdapter(
        client_id="id", redirect_uri="uri", client=mock_client
    )
    return adapter


class TestMedMijOauthTokenAdapter:
    @pytest.mark.asyncio
    async def test_get_access_token(
        self,
        mock_response: Response,
        token_adapter_mock: MedMijOauthTokenAdapter,
        mocker: MockerFixture,
    ) -> None:
        mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

        access_token: AccessTokenDTO = await token_adapter_mock.get_access_token(
            token_server_uri="http://localhost/token",
            code="test_code",
            correlation_id="test_correlation_id",
            medmij_request_id="test_medmij_request_id",
        )

        assert isinstance(access_token, AccessTokenDTO)
        assert access_token.access_token == ACCESS_TOKEN
        assert access_token.token_type == TOKEN_TYPE
        assert access_token.expires_in == EXPIRES_IN
        assert access_token.refresh_token == REFRESH_TOKEN
        assert access_token.scope == SCOPE

    @pytest.mark.asyncio
    async def test_refresh_access_token(
        self,
        token_adapter_mock: MedMijOauthTokenAdapter,
        mocker: MockerFixture,
    ) -> None:
        mocker.patch("httpx.AsyncClient.post", return_value=mock_response)

        access_token: AccessTokenDTO = await token_adapter_mock.refresh_access_token(
            token_server_uri="http://localhost/token",
            refresh_token="test_refresh_token",
            correlation_id="test_correlation_id",
            medmij_request_id="test_medmij_request_id",
        )

        assert isinstance(access_token, AccessTokenDTO)
        assert access_token.access_token == ACCESS_TOKEN
        assert access_token.token_type == TOKEN_TYPE
        assert access_token.expires_in == EXPIRES_IN
        assert access_token.refresh_token == REFRESH_TOKEN
        assert access_token.scope == SCOPE

    @pytest.mark.asyncio
    async def test_get_access_token_fails_with_a_400_error(
        self,
        test_client: TestClient,
        mock_response: Response,
        mock_client: AsyncOAuthClient,
        token_adapter_mock: MedMijOauthTokenAdapter,
        mocker: MockerFixture,
    ) -> None:
        mock_response = Response(
            status_code=400,
            request=Request("POST", "https://example.com"),
            json={
                "error": "invalid_request",
                "error_description": "The request is missing a required parameter.",
            },
        )

        mock_client.post.return_value = mock_response  # type: ignore[attr-defined]

        with pytest.raises(AuthorizationHttpException):
            await token_adapter_mock.get_access_token(
                token_server_uri="http://localhost/token",
                code="test_code",
                correlation_id="test_correlation_id",
                medmij_request_id="test_medmij_request_id",
            )

    @pytest.mark.asyncio
    async def test_get_access_token_fails_with_a_405_error(
        self,
        mock_response: Response,
        mock_client: AsyncOAuthClient,
        token_adapter_mock: MedMijOauthTokenAdapter,
        mocker: MockerFixture,
    ) -> None:
        mock_response = Response(
            status_code=405,
            request=Request("POST", "https://example.com"),
            content="Client error '405 Method Not Allowed' for url 'http://localhost:8001/token?grant_type=authorization_code&code=5a21f31d-4a00-4e47-aa97-501d6b296572&client_id=test.mgo.medmij%40denhaag&redirect_uri=http%3A%2F%2Flocalhost%3A8001%2Fauth%2Fcallback'\\nFor more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/405",
        )
        mock_client.post.return_value = mock_response  # type: ignore[attr-defined]

        with pytest.raises(AuthorizationHttpException) as e:
            await token_adapter_mock.get_access_token(
                token_server_uri="http://localhost/token",
                code="test_code",
                correlation_id="test_correlation_id",
                medmij_request_id="test_medmij_request_id",
            )
        assert e.value.status_code == 405

    @pytest.mark.asyncio
    async def test_get_access_token_fails_with_a_connect_timeout(
        self,
        mock_client: AsyncOAuthClient,
        token_adapter_mock: MedMijOauthTokenAdapter,
        mocker: MockerFixture,
    ) -> None:
        mock_client.post.side_effect = ConnectTimeout("Connection timed out")  # type: ignore[attr-defined]

        with pytest.raises(AuthorizationHttpException) as e:
            await token_adapter_mock.get_access_token(
                token_server_uri="http://localhost/token",
                code="test_code",
                correlation_id="test_correlation_id",
                medmij_request_id="test_medmij_request_id",
            )
        assert e.value.status_code == 500

    @pytest.mark.asyncio
    async def test_get_access_token_post_uses_data_not_params_is_successful(
        self,
        token_adapter_mock: MedMijOauthTokenAdapter,
        mock_client: AsyncOAuthClient,
    ) -> None:
        await token_adapter_mock.get_access_token(
            token_server_uri="https://example.com",
            code="code",
            correlation_id="cid",
            medmij_request_id="mid",
        )

        mock_client.post.assert_called_once()  # type: ignore[attr-defined]

        called_kwargs = mock_client.post.call_args.kwargs  # type: ignore[attr-defined]

        assert "data" in called_kwargs
        assert "params" not in called_kwargs
        assert (
            called_kwargs["headers"]["Content-Type"]
            == "application/x-www-form-urlencoded"
        )

        assert called_kwargs["data"] == {
            "grant_type": "authorization_code",
            "code": "code",
            "client_id": "id",
            "redirect_uri": "uri",
        }

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
