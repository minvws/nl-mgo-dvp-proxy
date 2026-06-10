from typing import Literal

import pytest
from faker import Faker
from fastapi import Response as FastApiResponse
from fastapi.testclient import TestClient
from httpx import Response
from inject import Binder
from pytest import mark
from pytest_mock import MockerFixture

from app.circuitbreaker.models import CircuitOpenException
from app.config.models import ForwardingConfig
from app.forwarding.constants import (
    DVA_TARGET_REQUEST_HEADER,
    MGO_DATASERVICE_ID_HEADER,
    MGO_HEALTHCARE_PROVIDER_ID_HEADER,
)
from app.forwarding.schemas import ForwardingRequestHeaders
from app.forwarding.services import ForwardingService
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
    ) -> None:
        response = test_client.get(
            "/fhir/patient",
            headers={
                DVA_TARGET_REQUEST_HEADER: "invalid-jwe",
            },
        )

        assert response.status_code == 400
        assert response.json()["context"] == {"field": DVA_TARGET_REQUEST_HEADER}

    def test_forward_client_request_success(
        self,
        test_client: TestClient,
        mocker: MockerFixture,
        dva_endpoint_jwe: str,
    ) -> None:
        mock_forwarding_service = mocker.Mock(ForwardingService)
        mock_response = FastApiResponse(
            content=b"response content",
            status_code=200,
            headers={"Content-Type": "application/fhir+json"},
        )

        mock_forwarding_service.get_resource.return_value = mock_response

        def bindings_override(binder: Binder) -> Binder:
            binder.bind(ForwardingService, mock_forwarding_service)
            return binder

        configure_bindings(bindings_override=bindings_override)

        response = test_client.get(
            "/fhir/patient?foo=bar",
            headers={
                DVA_TARGET_REQUEST_HEADER: dva_endpoint_jwe,
            },
        )

        assert response.status_code == 200
        assert response.content == b"response content"
        assert response.headers["Content-Type"] == "application/fhir+json"

    def test_forwarding_request_with_invalid_service_id_returns_validation_response(
        self,
        test_client: TestClient,
        dva_endpoint_jwe: str,
    ) -> None:
        response = test_client.get(
            "/fhir/patient?foo=bar",
            headers={
                DVA_TARGET_REQUEST_HEADER: dva_endpoint_jwe,
                MGO_DATASERVICE_ID_HEADER: "not-an-integer",
            },
        )

        assert response.status_code == 422
        assert response.json()["detail"][0]["loc"] == ["header", "X-MGO-DATASERVICE-ID"]
        assert response.json()["detail"][0]["input"] == "not-an-integer"

    @pytest.mark.parametrize(
        "provider_id,service_id,missing",
        [
            (None, None, MGO_HEALTHCARE_PROVIDER_ID_HEADER),
            ("provider", None, MGO_DATASERVICE_ID_HEADER),
            (None, 42, MGO_HEALTHCARE_PROVIDER_ID_HEADER),
        ],
    )
    def test_forwarding_request_without_required_provider_or_service_id_headers_returns_validation_response(
        self,
        test_client: TestClient,
        mocker: MockerFixture,
        dva_endpoint_jwe: str,
        provider_id: None | Literal["provider"],
        service_id: None | Literal[42],
        missing: str,
    ) -> None:
        forwarding_config = mocker.Mock(ForwardingConfig)
        forwarding_config.require_provider_and_service_id = True

        def bindings_override(binder: Binder) -> Binder:
            binder.bind(ForwardingConfig, forwarding_config)
            return binder

        configure_bindings(bindings_override)

        header_dict = {
            "accept": "application/fhir+json",
            DVA_TARGET_REQUEST_HEADER: dva_endpoint_jwe,
        }
        if provider_id is not None:
            header_dict[MGO_HEALTHCARE_PROVIDER_ID_HEADER] = provider_id
        if service_id is not None:
            header_dict[MGO_DATASERVICE_ID_HEADER] = str(service_id)

        response = test_client.get(
            "/fhir/patient?foo=bar",
            headers=header_dict,
        )

        assert response.status_code == 422
        assert response.json()["detail"] == f"Missing required header: {missing}"

    def test_router_uses_circuit_breaker_to_call_client_get(
        self,
        test_client: TestClient,
        mocker: MockerFixture,
        dva_endpoint_jwe: str,
    ) -> None:
        mock_circuit_breaker_call = mocker.patch(
            target="app.circuitbreaker.services.CircuitBreaker.call",
            new_callable=mocker.AsyncMock,
            return_value=Response(
                content="content: https://mock_url.com/api",
                status_code=200,
                headers={
                    "SOME_FORWARDED_HEADER": "hello",
                },
            ),
        )

        test_client.get(
            "/fhir/patient",
            headers={
                DVA_TARGET_REQUEST_HEADER: dva_endpoint_jwe,
                MGO_HEALTHCARE_PROVIDER_ID_HEADER: "test-provider-id",
                MGO_DATASERVICE_ID_HEADER: "123",
            },
        )

        assert mock_circuit_breaker_call.called

    def test_it_returns_502_when_circuit_breaker_is_open(
        self,
        test_client: TestClient,
        mocker: MockerFixture,
        dva_endpoint_jwe: str,
    ) -> None:
        mocker.patch(
            target="app.circuitbreaker.services.CircuitBreaker.call",
            side_effect=CircuitOpenException,
        )

        response = test_client.get(
            "/fhir/patient",
            headers={
                DVA_TARGET_REQUEST_HEADER: dva_endpoint_jwe,
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
        dva_endpoint_jwe: str,
    ) -> None:
        mock_forwarding_service = mocker.Mock(spec=ForwardingService)
        mock_response = FastApiResponse(
            content=b"response content",
            status_code=200,
            headers={"Content-Type": "application/fhir+json"},
        )
        header_values.update(
            {
                DVA_TARGET_REQUEST_HEADER: dva_endpoint_jwe,
            }
        )

        mock_forwarding_service.get_resource.return_value = mock_response

        def bindings_override(binder: Binder) -> Binder:
            binder.bind(ForwardingService, mock_forwarding_service)
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
        assert isinstance(headers, ForwardingRequestHeaders)
        assert headers.x_mgo_provider_id == expected_provider_id
        assert headers.x_mgo_service_id == expected_service_id
