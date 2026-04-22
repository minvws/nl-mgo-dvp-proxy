from faker import Faker
from fastapi import Response as FastApiResponse
from fastapi.testclient import TestClient
from httpx import Response
from inject import Binder
from pydantic import AnyHttpUrl
from pytest import mark
from pytest_mock import MockerFixture

from app.circuitbreaker.models import CircuitOpenException
from app.forwarding.constants import (
    DVA_TARGET_REQUEST_HEADER,
    MGO_DATASERVICE_ID_HEADER,
    MGO_HEALTHCARE_PROVIDER_ID_HEADER,
)
from app.forwarding.schemas import ForwardingRequest
from app.forwarding.services import ForwardingService
from app.security.dva_target.exceptions import DvaTargetAssertionError
from app.security.dva_target.services import DvaTargetAssertionParser
from tests.utils import configure_bindings


class TestRouter:
    def test_missing_dva_target_header_triggers_validation_response(
        self, test_client: TestClient
    ) -> None:
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

        response = test_client.get("/fhir/Patient")

        assert response.status_code == 422
        assert response.json() == expected_response

    def test_forward_client_request_returns_400_if_dva_target_parsing_fails(
        self,
        test_client: TestClient,
        mocker: MockerFixture,
        mock_dva_endpoint_jwe: str,
    ) -> None:
        mock_dva_target_assertion_parser = mocker.Mock(spec=DvaTargetAssertionParser)

        mock_dva_target_assertion_parser.parse.side_effect = DvaTargetAssertionError(
            "some parse error"
        )

        def bindings_override(binder: Binder) -> Binder:
            binder.bind(DvaTargetAssertionParser, mock_dva_target_assertion_parser)
            return binder

        configure_bindings(bindings_override=bindings_override)

        response = test_client.get(
            "/fhir/patient",
            headers={
                DVA_TARGET_REQUEST_HEADER: mock_dva_endpoint_jwe,
            },
        )

        assert response.status_code == 400
        assert response.json() == {"detail": "Failed to parse DVA target"}

        mock_dva_target_assertion_parser.parse.assert_called_once_with(
            serialized_jwe=mock_dva_endpoint_jwe
        )

    def test_forward_client_request_returns_422_if_dva_target_invalid_http_url(
        self, test_client: TestClient, mocker: MockerFixture, mock_dva_endpoint_jwe: str
    ) -> None:
        mock_dva_target_assertion_parser = mocker.Mock(spec=DvaTargetAssertionParser)

        mock_dva_target_assertion_parser.parse.return_value = "non-http-url-dva-target"

        def binding_override(binder: Binder) -> Binder:
            binder.bind(DvaTargetAssertionParser, mock_dva_target_assertion_parser)
            return binder

        configure_bindings(bindings_override=binding_override)

        response = test_client.get(
            "/fhir/patient",
            headers={
                DVA_TARGET_REQUEST_HEADER: mock_dva_endpoint_jwe,
            },
        )

        assert response.status_code == 422
        assert (
            response.json()["detail"][0]["msg"]
            == "Input should be a valid URL, relative URL without a base"
        )

    def test_forward_client_request_success(
        self,
        test_client: TestClient,
        mocker: MockerFixture,
        faker: Faker,
        mock_dva_endpoint_jwe: str,
    ) -> None:
        mock_forwarding_service = mocker.Mock(ForwardingService)
        mock_dva_target_assertion_parser = mocker.Mock(spec=DvaTargetAssertionParser)
        mock_response = FastApiResponse(
            content=b"response content",
            status_code=200,
            headers={"Content-Type": "application/fhir+json"},
        )

        mock_forwarding_service.get_resource.return_value = mock_response

        mock_dva_target_assertion_parser.parse.return_value = AnyHttpUrl(faker.url())

        def bindings_override(binder: Binder) -> Binder:
            binder.bind(ForwardingService, mock_forwarding_service)
            binder.bind(DvaTargetAssertionParser, mock_dva_target_assertion_parser)
            return binder

        configure_bindings(bindings_override=bindings_override)

        response = test_client.get(
            "/fhir/patient?foo=bar",
            headers={
                DVA_TARGET_REQUEST_HEADER: mock_dva_endpoint_jwe,
            },
        )

        assert response.status_code == 200
        assert response.content == b"response content"
        assert response.headers["Content-Type"] == "application/fhir+json"

    def test_router_uses_circuit_breaker_to_call_client_get(
        self,
        test_client: TestClient,
        mocker: MockerFixture,
        faker: Faker,
        mock_dva_endpoint_jwe: str,
    ) -> None:
        mock_dva_target_assertion_parser = mocker.Mock(spec=DvaTargetAssertionParser)

        mock_dva_target_assertion_parser.parse.return_value = AnyHttpUrl(faker.url())

        mock_circuit_breaker_call = mocker.patch(
            target="app.circuitbreaker.services.CircuitBreakerService.call",
            new_callable=mocker.AsyncMock,
            return_value=Response(
                content="content: https://mock_url.com/api",
                status_code=200,
                headers={
                    "SOME_FORWARDED_HEADER": "hello",
                },
            ),
        )

        def bindings_override(binder: Binder) -> Binder:
            binder.bind(DvaTargetAssertionParser, mock_dva_target_assertion_parser)
            return binder

        configure_bindings(bindings_override=bindings_override)

        test_client.get(
            "/fhir/patient",
            headers={
                DVA_TARGET_REQUEST_HEADER: mock_dva_endpoint_jwe,
                MGO_HEALTHCARE_PROVIDER_ID_HEADER: "test-provider-id",
                MGO_DATASERVICE_ID_HEADER: "123",
            },
        )

        assert mock_circuit_breaker_call.called

    def test_it_returns_502_when_circuit_breaker_is_open(
        self,
        test_client: TestClient,
        mocker: MockerFixture,
        faker: Faker,
        mock_dva_endpoint_jwe: str,
    ) -> None:
        mock_dva_target_assertion_parser = mocker.Mock(spec=DvaTargetAssertionParser)

        mock_dva_target_assertion_parser.parse.return_value = AnyHttpUrl(faker.url())

        mocker.patch(
            target="app.circuitbreaker.services.CircuitBreakerService.call",
            side_effect=CircuitOpenException,
        )

        def bindings_override(binder: Binder) -> Binder:
            binder.bind(DvaTargetAssertionParser, mock_dva_target_assertion_parser)
            return binder

        configure_bindings(bindings_override=bindings_override)

        response = test_client.get(
            "/fhir/patient",
            headers={
                DVA_TARGET_REQUEST_HEADER: mock_dva_endpoint_jwe,
                MGO_HEALTHCARE_PROVIDER_ID_HEADER: "test-provider-id",
                MGO_DATASERVICE_ID_HEADER: "123",
            },
        )

        assert response.status_code == 502
        assert response.json() == {"detail": "Bad gateway"}

    @mark.parametrize(
        "header_values,expected_provider_id,expected_service_id",
        [
            (
                {
                    MGO_HEALTHCARE_PROVIDER_ID_HEADER: "test-provider-id",
                    MGO_DATASERVICE_ID_HEADER: "456",
                },
                "test-provider-id",
                456,
            ),
            (
                {},
                None,
                None,
            ),
        ],
    )
    def test_forward_client_request_with_and_without_mgo_headers(
        self: object,
        test_client: TestClient,
        mocker: MockerFixture,
        faker: Faker,
        header_values: dict[str, str],
        expected_provider_id: str | None,
        expected_service_id: int | None,
        mock_dva_endpoint_jwe: str,
    ) -> None:
        mock_forwarding_service = mocker.Mock(spec=ForwardingService)
        mock_dva_target_assertion_parser = mocker.Mock(spec=DvaTargetAssertionParser)
        mock_response = FastApiResponse(
            content=b"response content",
            status_code=200,
            headers={"Content-Type": "application/fhir+json"},
        )
        header_values.update(
            {
                DVA_TARGET_REQUEST_HEADER: mock_dva_endpoint_jwe,
            }
        )

        mock_forwarding_service.get_resource.return_value = mock_response

        mock_dva_target_assertion_parser.parse.return_value = AnyHttpUrl(faker.url())

        def bindings_override(binder: Binder) -> Binder:
            binder.bind(ForwardingService, mock_forwarding_service)
            binder.bind(DvaTargetAssertionParser, mock_dva_target_assertion_parser)
            return binder

        configure_bindings(bindings_override=bindings_override)

        response = test_client.get(
            "/fhir/patient",
            headers=header_values,
        )

        assert response.status_code == 200
        mock_forwarding_service.get_resource.assert_called_once()
        call_args = mock_forwarding_service.get_resource.call_args
        headers = call_args[1]["headers"]
        assert isinstance(headers, ForwardingRequest)
        assert headers.x_mgo_provider_id == expected_provider_id
        assert headers.x_mgo_service_id == expected_service_id
