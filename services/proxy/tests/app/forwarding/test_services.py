from logging import Logger

import pytest
from fastapi import Request, Response
from httpx import AsyncClient
from httpx import Response as HttpxResponse
from pydantic import AnyHttpUrl
from pytest_mock import MockerFixture

from app.circuitbreaker.services import CircuitBreakerService
from app.forwarding.constants import (
    MEDMIJ_CORRELATION_ID_HEADER,
    MEDMIJ_REQUEST_ID_HEADER,
    FORWARD_URL_RESPONSE_HEADER,
)

from app.forwarding.models import DvaTarget
from app.forwarding.schemas import ForwardingRequest
from app.forwarding.services import ForwardingService


@pytest.fixture
def forwarding_service(mocker: MockerFixture) -> ForwardingService:
    forwarding_service: ForwardingService = ForwardingService(
        circuit_breaker=mocker.Mock(CircuitBreakerService),
        async_client=mocker.Mock(AsyncClient),
        logger=mocker.Mock(Logger),
        request_forwarding_log_handler=mocker.Mock(),
    )
    return forwarding_service


def test_get_forward_headers_is_successful(
    forwarding_service: ForwardingService,
) -> None:
    headers = ForwardingRequest(
        accept="application/fhir+json; fhirVersion=3.0",
        dva_target=AnyHttpUrl("https://example.com/resource"),
        oauth_access_token="token",
        x_mgo_provider_id="eenofanderezorgaanbieder",
        x_mgo_service_id=63,
    )  # type: ignore

    result_no_correlation: dict[str, str] = forwarding_service.get_forward_headers(
        headers=headers
    )
    assert result_no_correlation == {
        "Accept": "application/fhir+json; fhirVersion=3.0",
        MEDMIJ_REQUEST_ID_HEADER: result_no_correlation[
            MEDMIJ_REQUEST_ID_HEADER
        ],  # UUID is generated dynamically
        "Authorization": "Bearer token",
    }

    headers.correlation_id = "correlation_id"
    result: dict[str, str] = forwarding_service.get_forward_headers(headers=headers)
    assert result == {
        "Accept": "application/fhir+json; fhirVersion=3.0",
        MEDMIJ_REQUEST_ID_HEADER: result[
            MEDMIJ_REQUEST_ID_HEADER
        ],  # UUID is generated dynamically
        MEDMIJ_CORRELATION_ID_HEADER: "correlation_id",
        "Authorization": "Bearer token",
    }


def test_get_forward_headers_without_accept_header_and_correlation_is_successful(
    forwarding_service: ForwardingService,
) -> None:
    headers = ForwardingRequest(
        dva_target=AnyHttpUrl("https://example.com/resource"),
        oauth_access_token="token",
        x_mgo_provider_id="eenofanderezorgaanbieder",
        x_mgo_service_id=63,
    )  # type: ignore

    result_no_correlation: dict[str, str] = forwarding_service.get_forward_headers(
        headers=headers
    )
    assert result_no_correlation == {
        MEDMIJ_REQUEST_ID_HEADER: result_no_correlation[
            MEDMIJ_REQUEST_ID_HEADER
        ],  # UUID is generated dynamically
        "Authorization": "Bearer token",
    }

    headers.correlation_id = "correlation_id"
    result: dict[str, str] = forwarding_service.get_forward_headers(headers=headers)
    assert result == {
        MEDMIJ_REQUEST_ID_HEADER: result[
            MEDMIJ_REQUEST_ID_HEADER
        ],  # UUID is generated dynamically
        MEDMIJ_CORRELATION_ID_HEADER: "correlation_id",
        "Authorization": "Bearer token",
    }


@pytest.mark.asyncio
async def test_get_resource(mocker: MockerFixture) -> None:
    mock_circuit_breaker: CircuitBreakerService = mocker.Mock(CircuitBreakerService)
    mock_async_client: AsyncClient = mocker.Mock(AsyncClient)
    logger: Logger = mocker.Mock(Logger)
    forwarding_service: ForwardingService = ForwardingService(
        circuit_breaker=mock_circuit_breaker,
        async_client=mock_async_client,
        logger=logger,
        request_forwarding_log_handler=mocker.Mock(),
    )

    # Mock request and headers
    mock_request = mocker.Mock(Request)
    mock_request.url.path = "/resource"
    mock_request.url.query = "param=value"
    mock_headers = ForwardingRequest(
        accept="application/fhir+json; fhirVersion=3.0",
        dva_target=AnyHttpUrl("https://mock_target"),
        x_mgo_provider_id="eenofanderezorgaanbieder",
        x_mgo_service_id=63,
    )  # type: ignore

    # Mock responses for methods
    mock_dva_target = mocker.Mock(DvaTarget)
    mock_dva_target.target_url = "https://example.com"
    mocker.patch.object(DvaTarget, "from_dva_target_url", return_value=mock_dva_target)
    mocker.patch.object(
        forwarding_service,
        "generate_forward_url",
        return_value="https://example.com/resource?param=value",
    )
    mocker.patch.object(
        forwarding_service,
        "get_forward_headers",
        return_value={
            "Authorization": "Bearer token",
            MEDMIJ_REQUEST_ID_HEADER: MEDMIJ_REQUEST_ID_HEADER,
        },
    )

    mock_response: HttpxResponse = HttpxResponse(
        status_code=200, content=b"response content"
    )
    mock_circuit_breaker_call = mocker.patch.object(
        mock_circuit_breaker, "call", mocker.AsyncMock(return_value=mock_response)
    )

    result: Response = await forwarding_service.get_resource(
        request=mock_request, headers=mock_headers
    )

    mock_circuit_breaker_call.assert_awaited_once_with(
        identifier="https://example.com/resource?param=value",
        func=mock_async_client.get,
        url="https://example.com/resource?param=value",
        headers={
            "Authorization": "Bearer token",
            MEDMIJ_REQUEST_ID_HEADER: MEDMIJ_REQUEST_ID_HEADER,
        },
    )

    assert (
        result.headers[FORWARD_URL_RESPONSE_HEADER]
        == "https://example.com/resource?param=value"
    )
    assert result.status_code == mock_response.status_code


def test_get_forward_headers_with_empty_content(
    forwarding_service: ForwardingService,
) -> None:
    # Define headers with empty content using ForwardRequest
    headers_with_empty_content = ForwardingRequest(
        accept="application/fhir+json; fhirVersion=3.0",
        dva_target=AnyHttpUrl("https://example.com/resource"),
        oauth_access_token="",
        correlation_id="1",
        x_mgo_provider_id="eenofanderezorgaanbieder",
        x_mgo_service_id=63,
    )  # type: ignore

    result: dict[str, str] = forwarding_service.get_forward_headers(
        headers=headers_with_empty_content
    )

    expected_result = {
        "Accept": "application/fhir+json; fhirVersion=3.0",
        MEDMIJ_REQUEST_ID_HEADER: result[
            MEDMIJ_REQUEST_ID_HEADER
        ],  # UUID is generated dynamically
        "X-Correlation-ID": "1",
    }

    assert result == expected_result


@pytest.mark.parametrize(
    "target_url, path, query, expected_forward_url",
    [
        (
            "https://example.com/48",
            "/fhir/patient",
            "arg0=foo&arg1=bar",
            "https://example.com/48/fhir/patient?arg0=foo&arg1=bar",
        ),
        (
            "https://example.com",
            "/fhir/patient",
            "arg0=foo&arg1=bar",
            "https://example.com/fhir/patient?arg0=foo&arg1=bar",
        ),
        (
            "https://example.com/48",
            "/fhir/patient",
            "arg0=foo&arg1=bar",
            "https://example.com/48/fhir/patient?arg0=foo&arg1=bar",
        ),
        (
            "https://another.com/48",
            "/fhir/resource",
            "arg2=value",
            "https://another.com/48/fhir/resource?arg2=value",
        ),
        (
            "https://example.com/48",
            "/fhir/patient",
            {},
            "https://example.com/48/fhir/patient",
        ),
        (
            "http://localhost/48",
            "/api/resource",
            "id=123",
            "http://localhost/48/api/resource?id=123",
        ),
        (
            "https://example.com/48",
            "/fhir/patient",
            "include=value1&include=value2",
            "https://example.com/48/fhir/patient?include=value1&include=value2",
        ),
    ],
    ids=[
        "Generate Forward-URL with target_url, path, and query_params",
        "Generate Forward-URL with target_url (base url only), path, and query_params",
        "Generate Forward-URL with target_url (trailing slash) and query_params",
        "Generate Forward-URL with different target_url and query_params",
        "Generate Forward-URL without query_params",
        "Generate Forward-URL with target_url without domain extension",
        "Generate Forward-URL with two query arguments with same name but different values",
    ],
)
def test_generate_forward_url(
    forwarding_service: ForwardingService,
    target_url: str,
    path: str,
    query: str | None,
    expected_forward_url: str,
) -> None:
    target_url = forwarding_service.generate_forward_url(target_url, path, query)
    assert expected_forward_url == target_url


@pytest.mark.parametrize(
    "target_url, path, query, expected_error",
    [
        (
            "https://example.com",
            "api/resource",
            "param=value",
            "The path must start with a '/'",
        ),
        (
            "https://example.com",
            "/api/resource",
            "?param=value",
            "The query string must not start with a '?'",
        ),
    ],
)
def test_generate_forward_url_invalid_input(
    forwarding_service: ForwardingService,
    target_url: str,
    path: str,
    query: str | None,
    expected_error: str,
) -> None:
    with pytest.raises(ValueError, match=expected_error):
        forwarding_service.generate_forward_url(
            target_url=target_url, path=path, query=query
        )


def test_filter_response_headers(
    forwarding_service: ForwardingService, mocker: MockerFixture
) -> None:
    mock_response = HttpxResponse(
        content=b"response content",
        status_code=200,
        headers={"Transfer-Encoding": "chunked"},
    )

    headers_dict = dict(mock_response.headers)

    filtered_headers = forwarding_service.filter_response_headers(headers=headers_dict)

    assert "Transfer-Encoding" not in filtered_headers


@pytest.mark.asyncio
async def test_log_send_resource_request_warns_on_missing_headers(
    mocker: MockerFixture,
) -> None:
    logger = mocker.Mock(Logger)
    forwarding_service = ForwardingService(
        circuit_breaker=mocker.Mock(),
        async_client=mocker.Mock(),
        logger=logger,
        request_forwarding_log_handler=mocker.Mock(),
    )
    headers = ForwardingRequest(
        dva_target="https://example.com",
        accept=None,
        correlation_id=None,
        oauth_access_token=None,
        x_mgo_provider_id=None,
        x_mgo_service_id=None,
    )  # type: ignore
    request = mocker.Mock()
    request.url.path = "/resource"
    request.url.query = "foo=bar"

    mock_dva_target = mocker.Mock(DvaTarget)
    mock_dva_target.target_url = "https://example.com"
    mocker.patch.object(DvaTarget, "from_dva_target_url", return_value=mock_dva_target)
    mocker.patch.object(
        forwarding_service,
        "generate_forward_url",
        return_value="https://example.com/resource?param=value",
    )
    mocker.patch.object(
        forwarding_service,
        "get_forward_headers",
        return_value={
            "Authorization": "Bearer token",
            MEDMIJ_REQUEST_ID_HEADER: MEDMIJ_REQUEST_ID_HEADER,
        },
    )

    with pytest.raises(Exception):  # or HTTPException if that's what is raised
        await forwarding_service.get_resource(request=request, headers=headers)

    assert logger.warning.call_count >= 1
    assert "Missing required header(s)" in logger.warning.call_args[0][0]
