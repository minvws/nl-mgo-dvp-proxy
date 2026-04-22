from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from inject import Binder
from pydantic import ValidationError
from pytest_mock import MockerFixture

from app.authentication.exceptions import (
    AuthorizationHttpException,
    ExpirationTimeMissingException,
    ExpiredStateException,
)
from app.authentication.models import StateDTO
from app.authentication.services import MedMijOauthTokenService, StateService
from app.medmij_logging.enums import GrantType
from app.medmij_logging.factories import LogMessageFactory
from tests.utils import configure_bindings


@pytest.fixture
def mock_state_service(mocker: MockerFixture) -> StateService:
    mock: StateService = mocker.Mock(StateService)
    return mock


class TestGestStateEndpoint:
    def test_it_returns_200(
        self, test_client: TestClient, dva_endpoint_jwe: str
    ) -> None:
        response = test_client.post(
            f"/getstate",
            json={
                "authorization_server_url": dva_endpoint_jwe,
                "token_endpoint_url": dva_endpoint_jwe,
                "medmij_scope": "eenofanderezorgaanbieder",
                "client_target_url": "https://client.example.com/callback",
            },
            follow_redirects=False,
        )

        assert response.status_code == 200
        response_json = response.json()
        assert "url_to_request" in response_json

    @pytest.mark.parametrize(
        "missing_parameter",
        [
            "authorization_server_url",
            "token_endpoint_url",
            "medmij_scope",
            "client_target_url",
        ],
    )
    def test_it_returns_422_status_when_missing_parameter(
        self, missing_parameter: str, test_client: TestClient
    ) -> None:
        json = {
            "authorization_server_url": "https://authorization-server.com/authorize",
            "token_endpoint_url": "https://authorization-server.com/authorize",
            "medmij_scope": "eenofanderezorgaanbieder",
            "client_target_url": "https://client.example.com/callback",
        }

        del json[missing_parameter]
        response = test_client.post(
            f"/getstate",
            json=json,
            follow_redirects=False,
        )

        assert response.status_code == 422
        content = response.json()
        assert content["detail"][0]["loc"] == ["body", missing_parameter]

    @pytest.mark.parametrize(
        "empty_parameter",
        [
            "medmij_scope",
            "client_target_url",
        ],
    )
    def test_it_returns_400_status_when_required_parameter_empty(
        self, empty_parameter: str, test_client: TestClient, dva_endpoint_jwe: str
    ) -> None:
        json = {
            "authorization_server_url": dva_endpoint_jwe,
            "token_endpoint_url": dva_endpoint_jwe,
            "medmij_scope": "eenofanderezorgaanbieder",
            "client_target_url": "https://client.example.com/callback",
        }

        json[empty_parameter] = ""

        response = test_client.post("/getstate", json=json)

        assert response.status_code == 400
        content = response.json()
        assert content["detail"][0]["loc"] == [empty_parameter]


class TestAuthCallbackEndpoint:
    def test_handle_oauth_callback_success(
        self,
        mocker: MockerFixture,
        test_client: TestClient,
        mock_state_service: StateService,
    ) -> None:
        mock_state_service_decrypt_state_token = mocker.patch.object(
            mock_state_service, "decrypt_state_token"
        )
        mock_state_service_decrypt_state_token.return_value = StateDTO(
            token_endpoint_url="http://example.com/token",
            correlation_id="some_correlation_id",
            client_target_url="https://client.example.com/callback",
        )

        def bindings_override(binder: Binder) -> Binder:
            binder.bind(StateService, mock_state_service)
            return binder

        configure_bindings(bindings_override=bindings_override)

        response: Response = test_client.get(
            "/auth/callback",
            params={"state": "xyz", "code": "test_code"},
            follow_redirects=False,
        )

        assert response.status_code == 307
        assert (
            response.headers["location"]
            == "https://client.example.com/callback?access_code=mocked_access_token&token_type=Bearer&expires_in=900&refresh_code=mocked_refresh_token&scope=48%2049&correlation_id=some_correlation_id"
        )

    def test_handle_oauth_callback_expired_token(
        self,
        mocker: MockerFixture,
        test_client: TestClient,
        mock_state_service: StateService,
    ) -> None:
        mock_state_service_decrypt_state_token = mocker.patch.object(
            mock_state_service, "decrypt_state_token"
        )
        mock_state_service_decrypt_state_token.side_effect = ExpiredStateException(
            "State token has expired"
        )

        self.__bind_mock(state_service=mock_state_service)

        response: Response = test_client.get(
            "/auth/callback", params={"state": "xyz", "code": "test_code"}
        )

        assert response.status_code == 400
        assert response.json() == {
            "detail": "State token has expired",
            "status_code": 400,
        }

    def test_handle_oauth_callback_invalid_state(
        self,
        mocker: MockerFixture,
        test_client: TestClient,
        mock_state_service: StateService,
    ) -> None:
        mock_state_service_decrypt_state_token = mocker.patch.object(
            mock_state_service, "decrypt_state_token"
        )
        mock_state_service_decrypt_state_token.side_effect = (
            ExpirationTimeMissingException("No expiration time found in State token")
        )

        self.__bind_mock(state_service=mock_state_service)

        response: Response = test_client.get(
            "/auth/callback", params={"state": "invalid_state", "code": "test_code"}
        )

        assert response.status_code == 400
        assert response.json() == {
            "detail": "No expiration time found in State token",
            "status_code": 400,
        }

    def test_handle_oauth_callback_missing_code(
        self,
        test_client: TestClient,
        mock_state_service: StateService,
    ) -> None:
        self.__bind_mock(state_service=mock_state_service)

        response: Response = test_client.get("/auth/callback", params={"state": "xyz"})

        assert response.status_code == 422
        json_response = response.json()
        assert json_response["detail"][0]["loc"] == ["query", "code"]
        assert json_response["detail"][0]["msg"] == "Field required"

    def test_handle_oauth_callback_empty_code(
        self,
        test_client: TestClient,
        mock_state_service: StateService,
    ) -> None:
        self.__bind_mock(state_service=mock_state_service)

        with pytest.raises(ValidationError, match='Property "code" may not be empty'):
            test_client.get("/auth/callback", params={"state": "xyz", "code": ""})

    def test_handle_oauth_callback_missing_state(
        self,
        test_client: TestClient,
        mock_state_service: StateService,
    ) -> None:
        self.__bind_mock(state_service=mock_state_service)

        response: Response = test_client.get(
            "/auth/callback", params={"code": "test_code"}
        )

        assert response.status_code == 422
        json_response = response.json()
        assert json_response["detail"][0]["loc"] == ["query", "state"]
        assert json_response["detail"][0]["msg"] == "Field required"

    def test_handle_oauth_error_callback_success(
        self, test_client: TestClient, mock_state_service: StateService
    ) -> None:
        self.__bind_mock(state_service=mock_state_service)

        error: int = 502
        error_description: str = "Authorization failed."

        response = test_client.get(
            "/auth/callback",
            params={"error": error, "error_description": error_description},
        )

        assert response.status_code == error
        assert response.content.decode() == "Bad Gateway"

    def test_handle_oauth_callback_with_token_server_exception(
        self,
        mocker: MockerFixture,
        test_client: TestClient,
        mock_state_service: StateService,
    ) -> None:
        mock_state_service_decrypt_state_token = mocker.patch.object(
            mock_state_service, "decrypt_state_token"
        )
        mock_state_service_decrypt_state_token.return_value = StateDTO(
            token_endpoint_url="http://example.com/token",
            correlation_id="some_correlation_id",
            client_target_url="https://client.example.com/callback",
        )

        mock_token_service = mocker.Mock(MedMijOauthTokenService)
        token_service_mock_retrieve_access_token = mocker.patch.object(
            mock_token_service, "retrieve_access_token"
        )
        token_service_mock_retrieve_access_token.side_effect = (
            AuthorizationHttpException(
                status_code=502, detail={"error": "Invalid request"}
            )
        )

        def bindings_override(binder: Binder) -> Binder:
            binder.bind(StateService, mock_state_service)
            binder.bind(MedMijOauthTokenService, mock_token_service)
            return binder

        configure_bindings(bindings_override=bindings_override)

        response: Response = test_client.get(
            "/auth/callback",
            params={"state": "xyz", "code": "test_code"},
            follow_redirects=False,
        )

        assert response.status_code == 502
        assert response.content.decode() == "Bad Gateway"

    def __bind_mock(self, state_service: StateService) -> None:
        def bindings_override(binder: Binder) -> Binder:
            binder.bind(StateService, state_service)
            return binder

        configure_bindings(bindings_override=bindings_override)

    def test_when_auth_callback_requested_then_a_send_token_request_should_be_logged(
        self, test_client: TestClient, mocker: MockerFixture
    ) -> None:
        mock_state_service: StateService = mocker.Mock(spec=StateService)

        mock_state_service_decrypt_state_token = mocker.patch.object(
            mock_state_service, "decrypt_state_token"
        )

        mock_state_service_decrypt_state_token.return_value = StateDTO(
            token_endpoint_url="http://example.com/token",
            correlation_id="some_correlation_id",
            client_target_url="https://client.example.com/callback",
        )

        def bindings_override(binder: Binder) -> Binder:
            binder.bind(StateService, mock_state_service)
            return binder

        configure_bindings(bindings_override=bindings_override)

        spy = mocker.spy(LogMessageFactory, "send_token_request")

        test_client.get(
            "/auth/callback",
            params={"state": "xyz", "code": "test_code"},
            follow_redirects=False,
        )

        spy.assert_called_once_with(
            mocker.ANY,
            method="POST",
            server_id="example.com",
            session_id="some_correlation_id",
            token_server_uri="http://example.com/token",
            trace_id=mocker.ANY,
            grant_type=GrantType.AUTHORIZATION_CODE,
        )


class TestAuthRefreshEndpoint:
    def test_it_returns_200(
        self, test_client: TestClient, dva_endpoint_jwe: str
    ) -> None:
        query_params = urlencode(
            {
                "token_endpoint_url": dva_endpoint_jwe,
                "refresh_token": "test_refresh_token",
                "correlation_id": "xyz",
            }
        )
        response: Response = test_client.get(
            f"/auth/refresh?{query_params}",
            follow_redirects=False,
        )

        assert response.status_code == 200
        assert response.json() == {
            "access_token": "mocked_access_token",
            "token_type": "Bearer",
            "expires_in": 900,
            "refresh_token": "mocked_refresh_token",
            "scope": "48 49",
        }

    @pytest.mark.parametrize(
        "missing_parameter",
        [
            "token_endpoint_url",
            "refresh_token",
            "correlation_id",
        ],
    )
    def test_it_returns_422_status_when_missing_parameter(
        self, missing_parameter: str, test_client: TestClient, dva_endpoint_jwe: str
    ) -> None:
        query_params = {
            "token_endpoint_url": dva_endpoint_jwe,
            "refresh_token": "test_refresh_token",
            "correlation_id": "xyz",
        }

        del query_params[missing_parameter]

        response = test_client.get("/auth/refresh", params=query_params)

        assert response.status_code == 422
        content = response.json()
        assert content["detail"][0]["loc"] == ["query", missing_parameter]

    @pytest.mark.parametrize(
        "empty_parameter",
        [
            "refresh_token",
            "correlation_id",
        ],
    )
    def test_it_returns_400_status_when_required_parameter_empty(
        self, empty_parameter: str, test_client: TestClient, dva_endpoint_jwe: str
    ) -> None:
        query_params = {
            "token_endpoint_url": dva_endpoint_jwe,
            "refresh_token": "test_refresh_token",
            "correlation_id": "xyz",
        }

        query_params[empty_parameter] = ""

        response = test_client.get("/auth/refresh", params=query_params)

        assert response.status_code == 400
        content = response.json()
        assert content["detail"][0]["loc"] == [empty_parameter]
