import inject
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
from app.config.models import AppConfig
from app.forwarding.signing.exceptions import (
    DisallowedTargetHost,
    InvalidTargetUrlSignature,
)
from app.forwarding.signing.services import DvaTargetVerifier, SignedUrlVerifier
from app.medmij_logging.enums import GrantType
from app.medmij_logging.factories import LogMessageFactory
from tests.utils import configure_bindings, load_app_config


@pytest.fixture
def mock_state_service(mocker: MockerFixture) -> StateService:
    mock: StateService = mocker.Mock(StateService)
    return mock


class TestGestStateEndpoint:
    def test_it_uses_the_required_parameters_to_build_the_response(
        self,
        mocker: MockerFixture,
        test_client: TestClient,
        mock_state_service: StateService,
    ) -> None:
        mock_state_service_generate_state_token = mocker.patch.object(
            mock_state_service, "generate_state_token"
        )
        mock_state_service_generate_state_token.return_value = "generated-state"

        def override_bindings(binder: Binder) -> Binder:
            binder.bind(StateService, mock_state_service)
            binder.bind(DvaTargetVerifier, mocker.Mock(DvaTargetVerifier))
            return binder

        configure_bindings(bindings_override=override_bindings)

        response = test_client.post(
            f"/getstate",
            json={
                "authorization_server_url": "https://authorization-server.com/authorize",
                "token_endpoint_url": "https://authorization-server.com/authorize",
                "medmij_scope": "eenofanderezorgaanbieder",
                "client_target_url": "https://client.example.com/callback",
            },
            follow_redirects=False,
        )

        assert response.status_code == 200
        content = response.json()
        assert "scope=eenofanderezorgaanbieder" in content["url_to_request"]
        assert "state=generated-state" in content["url_to_request"]

        inject.clear()

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
        assert content["detail"][0]["type"] == "missing"
        assert content["detail"][0]["loc"] == ["body", missing_parameter]
        assert content["detail"][0]["msg"] == "Field required"
        assert content["detail"][0]["input"] == json

    @pytest.mark.parametrize(
        "signature_valid, expected_status",
        [
            (True, 200),
            (False, 403),
        ],
    )
    def test_it_verifies_the_signature_of_the_supplied_target_url(
        self,
        test_client: TestClient,
        mocker: MockerFixture,
        signature_valid: bool,
        expected_status: int,
    ) -> None:
        verifier = mocker.Mock(spec=SignedUrlVerifier)
        if signature_valid:
            verifier.verify.return_value = None
        else:
            verifier.verify.side_effect = InvalidTargetUrlSignature(
                ["Invalid signature"]
            )

        configure_bindings(lambda binder: binder.bind(SignedUrlVerifier, verifier))

        response = test_client.post(
            f"/getstate",
            json={
                "authorization_server_url": "https://authorization-server.com/authorize?mgo_signature=123",
                "token_endpoint_url": "https://authorization-server.com/authorize?mgo_signature=123",
                "medmij_scope": "eenofanderezorgaanbieder",
                "client_target_url": "https://client.example.com/callback",
            },
            follow_redirects=False,
        )

        assert response.status_code == expected_status

    def test_it_returns_http_403_when_target_host_is_in_blocklist(
        self, test_client: TestClient, mocker: MockerFixture
    ) -> None:
        verifier = mocker.Mock(spec=DvaTargetVerifier)
        verifier.verify.side_effect = DisallowedTargetHost(
            hostname="https://sketchyhost.com"
        )
        configure_bindings(lambda binder: binder.bind(DvaTargetVerifier, verifier))

        response = test_client.post(
            f"/getstate",
            json={
                "authorization_server_url": "https://authorization-server.com/authorize",
                "token_endpoint_url": "https://authorization-server.com/authorize?mgo_signature=123",
                "medmij_scope": "eenofanderezorgaanbieder",
                "client_target_url": "https://client.example.com/callback",
            },
            follow_redirects=False,
        )

        assert response.status_code == 403
        assert response.json() == {"detail": "Target host is disallowed."}


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

        def bind_services(binder: Binder) -> Binder:
            binder.bind(StateService, mock_state_service)
            return binder

        configure_bindings(bindings_override=bind_services)

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
        mocker: MockerFixture,
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
        mocker: MockerFixture,
        test_client: TestClient,
        mock_state_service: StateService,
    ) -> None:
        self.__bind_mock(state_service=mock_state_service)

        with pytest.raises(ValidationError, match='Property "code" may not be empty'):
            test_client.get("/auth/callback", params={"state": "xyz", "code": ""})

    def test_handle_oauth_callback_missing_state(
        self,
        mocker: MockerFixture,
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

        def bind_services(binder: Binder) -> Binder:
            binder.bind(StateService, mock_state_service)
            binder.bind(MedMijOauthTokenService, mock_token_service)
            return binder

        configure_bindings(bindings_override=bind_services)

        response: Response = test_client.get(
            "/auth/callback",
            params={"state": "xyz", "code": "test_code"},
            follow_redirects=False,
        )

        assert response.status_code == 502
        assert response.content.decode() == "Bad Gateway"

    def __bind_mock(self, state_service: StateService) -> None:
        def bind_services(binder: Binder) -> Binder:
            binder.bind(StateService, state_service)
            return binder

        configure_bindings(bindings_override=bind_services)

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

        def bind_services(binder: Binder) -> Binder:
            binder.bind(StateService, mock_state_service)
            return binder

        configure_bindings(bindings_override=bind_services)

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
    def test_handle_auth_refresh_success(
        self,
        mocker: MockerFixture,
        test_client: TestClient,
    ) -> None:
        def override_bindings(binder: Binder) -> Binder:
            binder.bind(SignedUrlVerifier, mocker.Mock(spec=SignedUrlVerifier))
            binder.bind(DvaTargetVerifier, mocker.Mock(spec=DvaTargetVerifier))
            return binder

        configure_bindings(
            bindings_override=override_bindings,
        )

        response: Response = test_client.get(
            "/auth/refresh",
            params={
                "token_endpoint_url": "http://example.com/token",
                "refresh_token": "test_refresh_token",
                "correlation_id": "xyz",
            },
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

    def test_refres_endpoint_required_signed_url(
        self,
        mocker: MockerFixture,
        test_client: TestClient,
    ) -> None:
        mock_signed_url_verifier = mocker.Mock(spec=SignedUrlVerifier)
        mock_signed_url_verifier.verify.side_effect = InvalidTargetUrlSignature(
            ["Invalid signature"]
        )

        def override_bindings(binder: Binder) -> Binder:
            binder.bind(
                SignedUrlVerifier,
                mock_signed_url_verifier,
            )
            return binder

        configure_bindings(
            bindings_override=override_bindings,
        )

        response: Response = test_client.get(
            "/auth/refresh",
            params={
                "token_endpoint_url": "http://example.com/token",
                "refresh_token": "test_refresh_token",
                "correlation_id": "xyz",
            },
            follow_redirects=False,
        )

        assert response.status_code == 403
        assert response.json() == {"detail": "Missing target URL signature."}

    def test_refresh_does_not_require_signed_url_when_signature_verification_is_disabled(
        self,
        mocker: MockerFixture,
        test_client: TestClient,
    ) -> None:
        config: AppConfig = load_app_config()
        config.signature_validation.verify_signed_requests = False

        configure_bindings(
            bindings_override=lambda binder: binder.bind(AppConfig, config),
        )

        response: Response = test_client.get(
            "/auth/refresh",
            params={
                "token_endpoint_url": "http://example.com/token",
                "refresh_token": "test_refresh_token",
                "correlation_id": "xyz",
            },
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

    def test_refresh_does_not_allow_disallowed_target_host(
        self,
        mocker: MockerFixture,
        test_client: TestClient,
    ) -> None:
        mock_dva_target_verifier = mocker.Mock(spec=DvaTargetVerifier)
        mock_dva_target_verifier.verify.side_effect = DisallowedTargetHost(
            hostname="https://sketchyhost.com"
        )

        def override_bindings(binder: Binder) -> Binder:
            binder.bind(DvaTargetVerifier, mock_dva_target_verifier)
            return binder

        configure_bindings(
            bindings_override=override_bindings,
        )

        response: Response = test_client.get(
            "/auth/refresh",
            params={
                "token_endpoint_url": "http://example.com/token",
                "refresh_token": "test_refresh_token",
                "correlation_id": "xyz",
            },
            follow_redirects=False,
        )

        assert response.status_code == 403
        assert response.json() == {"detail": "Target host is disallowed."}

    def test_handle_auth_refresh_missing_refresh_token(
        self,
        mocker: MockerFixture,
        test_client: TestClient,
        mock_state_service: StateService,
    ) -> None:
        configure_bindings(lambda binder: binder.bind(StateService, mock_state_service))

        response: Response = test_client.get("/auth/refresh", params={"state": "xyz"})

        assert response.status_code == 422
        json_response = response.json()
        assert json_response["detail"][0]["loc"] == ["query", "refresh_token"]
        assert json_response["detail"][0]["msg"] == "Field required"

    def test_handle_auth_refresh_empty_refresh_token(
        self,
        mocker: MockerFixture,
        test_client: TestClient,
        mock_state_service: StateService,
    ) -> None:
        configure_bindings(lambda binder: binder.bind(StateService, mock_state_service))

        with pytest.raises(
            ValidationError, match='Property "refresh_token" may not be empty'
        ):
            test_client.get(
                "/auth/refresh",
                params={
                    "token_endpoint_url": "http://example.com/token",
                    "refresh_token": "",
                    "correlation_id": "xyz",
                },
            )
