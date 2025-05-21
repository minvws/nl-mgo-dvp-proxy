from fastapi import Response as FastApiResponse
from fastapi.testclient import TestClient
from httpx import Response
from inject import Binder
from pytest_mock import MockerFixture

from app.circuitbreaker.models import CircuitOpenException
from app.forwarding.constants import (
    DVA_TARGET_REQUEST_HEADER,
    TARGET_URL_SIGNATURE_QUERY_PARAM,
)
from app.forwarding.models import DvaTarget, TargetUrlSignature
from app.forwarding.services import ForwardingService
from app.forwarding.signing.exceptions import InvalidTargetUrlSignature
from app.forwarding.signing.services import SignedUrlVerifier
from tests.utils import configure_bindings


class TestRouter:
    def test_handle_missing_header(self, test_client: TestClient) -> None:
        response = test_client.get("/48/fhir/Patient")
        assert response.status_code == 422

        expected_response = {
            "detail": [
                {
                    "type": "missing",
                    "loc": ["header", DVA_TARGET_REQUEST_HEADER],
                    "msg": "Field required",
                    "input": None,
                },
            ]
        }

        assert response.json() == expected_response

    def test_get_proxy_returns_403_signature_not_provided(
        self, test_client: TestClient
    ) -> None:
        response = test_client.get(
            "/fhir/patient",
            headers={
                DVA_TARGET_REQUEST_HEADER: "https://examplebar.com",
            },
        )

        assert response.status_code == 403
        assert response.json() == {"detail": "Invalid signature"}

    def test_get_proxy_returns_403_invalid_signature(
        self,
        test_client: TestClient,
        mocker: MockerFixture,
    ) -> None:
        configure_bindings(
            lambda binder: binder.bind(
                SignedUrlVerifier,
                mocker.Mock(
                    SignedUrlVerifier,
                    verify=mocker.Mock(
                        side_effect=InvalidTargetUrlSignature(["invalid"]),
                    ),
                ),
            )
        )

        response = test_client.get(
            "/fhir/patient",
            headers={
                DVA_TARGET_REQUEST_HEADER: f"https://examplefoo.com?{TARGET_URL_SIGNATURE_QUERY_PARAM}=invalid_signature",
            },
        )

        assert response.status_code == 403
        assert response.json() == {"detail": "Invalid signature"}

    def test_forward_client_request_success(
        self, test_client: TestClient, mocker: MockerFixture
    ) -> None:
        mock_signed_url_verifier = mocker.Mock(SignedUrlVerifier)

        mock_forwarding_service = mocker.Mock(ForwardingService)

        mock_forwarding_service.get_and_verify_dva_target = mocker.AsyncMock(
            return_value=DvaTarget(
                target_url="https://example.com/48",
                signature=TargetUrlSignature(value="mysignature"),
            )
        )
        mock_forwarding_service.get_forward_headers = mocker.Mock(
            return_value={"Authorization": "Bearer token"}
        )

        mock_response = FastApiResponse(
            content=b"response content",
            status_code=200,
            headers={"Content-Type": "application/fhir+json"},
        )

        mock_forwarding_service.get_resource = mocker.AsyncMock(
            return_value=mock_response
        )

        mock_forwarding_service.filter_response_headers = mocker.Mock(
            return_value={"Content-Type": "application/fhir+json"}
        )

        def bind_services(binder: Binder) -> Binder:
            binder.bind(SignedUrlVerifier, mock_signed_url_verifier)
            binder.bind(ForwardingService, mock_forwarding_service)
            return binder

        configure_bindings(bindings_override=bind_services)

        response = test_client.get(
            "/fhir/patient?foo=bar",
            headers={
                DVA_TARGET_REQUEST_HEADER: f"https://example.com/48?{TARGET_URL_SIGNATURE_QUERY_PARAM}=valid",
            },
        )

        assert response.status_code == 200
        assert response.content == b"response content"
        assert response.headers["Content-Type"] == "application/fhir+json"

    def test_router_uses_circuit_breaker_to_call_client_get(
        self,
        test_client: TestClient,
        mocker: MockerFixture,
    ) -> None:
        mock_circuit_breaker_call = mocker.patch(
            target="app.circuitbreaker.services.CircuitBreakerService.call",
            return_value=Response(
                content="content: https://mock_url.com/api",
                status_code=200,
                headers={
                    "SOME_FORWARDED_HEADER": "hello",
                },
            ),
        )

        configure_bindings(
            lambda binder: binder.bind(
                SignedUrlVerifier,
                mocker.Mock(SignedUrlVerifier),
            )
        )

        response = test_client.get(
            "/fhir/patient",
            headers={
                DVA_TARGET_REQUEST_HEADER: f"https://dva_target?{TARGET_URL_SIGNATURE_QUERY_PARAM}=valid",
            },
        )

        assert mock_circuit_breaker_call.called

    def test_it_returns_502_when_circuit_breaker_is_open(
        self,
        test_client: TestClient,
        mocker: MockerFixture,
    ) -> None:
        mocker.patch(
            target="app.circuitbreaker.services.CircuitBreakerService.call",
            side_effect=CircuitOpenException,
        )

        configure_bindings(
            lambda binder: binder.bind(
                SignedUrlVerifier,
                mocker.Mock(SignedUrlVerifier),
            )
        )

        response = test_client.get(
            "/fhir/patient",
            headers={
                DVA_TARGET_REQUEST_HEADER: f"https://dva_target?{TARGET_URL_SIGNATURE_QUERY_PARAM}=valid",
            },
        )

        assert response.status_code == 502
        assert response.json() == {"detail": "Bad gateway"}
