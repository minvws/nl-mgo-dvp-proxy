from collections.abc import Callable
from logging import Logger
from typing import TypeAlias

from faker import Faker
from fastapi import HTTPException, Request, Response
from httpx import AsyncClient, TimeoutException
from httpx import Response as HttpxResponse
from pytest import fixture, mark, raises
from pytest_mock import MockerFixture, MockType

from app.circuitbreaker.models import CircuitOpenException
from app.circuitbreaker.services import CircuitBreaker
from app.forwarding.constants import (
    FORWARD_URL_RESPONSE_HEADER,
    MEDMIJ_CORRELATION_ID_HEADER,
    MEDMIJ_REQUEST_ID_HEADER,
)
from app.forwarding.events import RequestFinished, RequestInit, RequestTimeout
from app.forwarding.factories import MediaResourceGatewayHeaderFactory
from app.forwarding.schemas import (
    ForwardingRequestHeaders,
    ForwardMediaResourceRequestHeaders,
)
from app.forwarding.services import ForwardingService, MediaResourceGateway
from app.observer.services import EventManager

MockDependencies: TypeAlias = tuple[
    MediaResourceGateway,
    MockType,
    MockType,
    MockType,
    MockType,
]


@fixture
def forwarding_service(mocker: MockerFixture) -> ForwardingService:
    forwarding_service: ForwardingService = ForwardingService(
        circuit_breaker=mocker.Mock(CircuitBreaker),
        async_client=mocker.Mock(AsyncClient),
        logger=mocker.Mock(Logger),
        request_forwarding_log_handler=mocker.Mock(),
    )
    return forwarding_service


def test_get_forward_headers_is_successful(
    forwarding_service: ForwardingService,
) -> None:
    headers_without_correlation = ForwardingRequestHeaders(
        accept="application/fhir+json; fhirVersion=3.0",
        dva_target_url="https://example.com/resource",
        oauth_access_token="token",
        x_mgo_provider_id="eenofanderezorgaanbieder",
        x_mgo_service_id=63,
        correlation_id=None,
    )

    result_without_correlation = forwarding_service.get_forward_headers(
        headers=headers_without_correlation
    )
    assert result_without_correlation == {
        "Accept": "application/fhir+json; fhirVersion=3.0",
        MEDMIJ_REQUEST_ID_HEADER: result_without_correlation[
            MEDMIJ_REQUEST_ID_HEADER  # UUID is generated dynamically
        ],
        "Authorization": "Bearer token",
    }

    headers_with_correlation = ForwardingRequestHeaders(
        accept="application/fhir+json; fhirVersion=3.0",
        dva_target_url="https://example.com/resource",
        oauth_access_token="token",
        x_mgo_provider_id="eenofanderezorgaanbieder",
        x_mgo_service_id=63,
        correlation_id="correlation_id",
    )

    result_without_correlation = forwarding_service.get_forward_headers(
        headers=headers_with_correlation
    )
    assert result_without_correlation == {
        "Accept": "application/fhir+json; fhirVersion=3.0",
        MEDMIJ_REQUEST_ID_HEADER: result_without_correlation[
            MEDMIJ_REQUEST_ID_HEADER  # UUID is generated dynamically
        ],
        MEDMIJ_CORRELATION_ID_HEADER: "correlation_id",
        "Authorization": "Bearer token",
    }


def test_get_forward_headers_skips_accept_header_when_not_present_in_request(
    forwarding_service: ForwardingService,
) -> None:
    headers_without_accept = ForwardingRequestHeaders(
        accept=None,
        dva_target_url="https://example.com/resource",
        oauth_access_token="token",
        x_mgo_provider_id="eenofanderezorgaanbieder",
        x_mgo_service_id=63,
        correlation_id=None,
    )

    result = forwarding_service.get_forward_headers(headers=headers_without_accept)
    assert "Accept" not in result


def test_get_forward_headers_without_accept_header_and_correlation_is_successful(
    forwarding_service: ForwardingService,
) -> None:
    headers_without_correlation_id = ForwardingRequestHeaders(
        dva_target_url="https://example.com/resource",
        oauth_access_token="token",
        x_mgo_provider_id="eenofanderezorgaanbieder",
        x_mgo_service_id=63,
        correlation_id=None,
        accept="application/fhir+json; fhirVersion=3.0",
    )

    result_no_correlation = forwarding_service.get_forward_headers(
        headers=headers_without_correlation_id
    )
    assert result_no_correlation == {
        "MedMij-Request-ID": result_no_correlation[
            "MedMij-Request-ID"  # UUID is generated dynamically
        ],
        "Accept": "application/fhir+json; fhirVersion=3.0",
        "Authorization": "Bearer token",
    }

    headers_with_correlation_id = ForwardingRequestHeaders(
        dva_target_url="https://example.com/resource",
        oauth_access_token="token",
        x_mgo_provider_id="eenofanderezorgaanbieder",
        x_mgo_service_id=63,
        correlation_id="correlation_id",
        accept="application/fhir+json; fhirVersion=3.0",
    )

    result = forwarding_service.get_forward_headers(headers=headers_with_correlation_id)

    assert result == {
        MEDMIJ_REQUEST_ID_HEADER: result[
            MEDMIJ_REQUEST_ID_HEADER  # UUID is generated dynamically
        ],
        MEDMIJ_CORRELATION_ID_HEADER: "correlation_id",
        "Accept": "application/fhir+json; fhirVersion=3.0",
        "Authorization": "Bearer token",
    }


@mark.asyncio
async def test_get_resource(mocker: MockerFixture) -> None:
    mock_circuit_breaker: CircuitBreaker = mocker.Mock(CircuitBreaker)
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
    mock_headers = ForwardingRequestHeaders(
        accept="application/fhir+json; fhirVersion=3.0",
        dva_target_url="https://mock_target",
        x_mgo_provider_id="eenofanderezorgaanbieder",
        x_mgo_service_id=63,
        oauth_access_token=None,
        correlation_id=None,
    )

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
        path=mock_request.url.path, request=mock_request, headers=mock_headers
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
    headers_with_empty_content = ForwardingRequestHeaders(
        accept="application/fhir+json; fhirVersion=3.0",
        dva_target_url="https://example.com/resource",
        oauth_access_token="",
        correlation_id="1",
        x_mgo_provider_id="eenofanderezorgaanbieder",
        x_mgo_service_id=63,
    )

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


@mark.parametrize(
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
        (
            "https://dva.interoplab.eu/ontwikkel/verplicht/fhir",
            "/fhir/MedicationRequest",
            "category=http://snomed.info/sct|16076005&_include=MedicationRequest:medication",
            "https://dva.interoplab.eu/ontwikkel/verplicht/fhir/MedicationRequest?category=http://snomed.info/sct|16076005&_include=MedicationRequest:medication",
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
        "Generate Forward-URL without duplicating fhir segment when target already ends in /fhir",
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


@mark.parametrize(
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
    with raises(ValueError, match=expected_error):
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


@mark.asyncio
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
    headers = ForwardingRequestHeaders(
        dva_target_url="https://example.com",
        accept=None,
        correlation_id=None,
        oauth_access_token=None,
        x_mgo_provider_id=None,
        x_mgo_service_id=None,
    )
    request = mocker.Mock()
    request.url.path = "/resource"
    request.url.query = "foo=bar"

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

    with raises(Exception):  # or HTTPException if that's what is raised
        await forwarding_service.get_resource(
            path=request.url.path, request=request, headers=headers
        )

    assert logger.warning.call_count >= 1
    assert "Missing required header(s)" in logger.warning.call_args[0][0]


class TestMediaResourceGateway:
    @fixture
    def mock_dependencies(
        self,
        mocker: MockerFixture,
        faker: Faker,
    ) -> MockDependencies:
        mock_event_manager: MockType = mocker.Mock(spec=EventManager)
        mock_circuit_breaker: MockType = mocker.Mock(spec=CircuitBreaker)
        mock_circuit_breaker.call = mocker.AsyncMock()
        mock_async_client: MockType = mocker.Mock(spec=AsyncClient)
        mock_header_factory: MockType = mocker.Mock(
            spec=MediaResourceGatewayHeaderFactory
        )

        mock_request: MockType = mocker.Mock(spec=Request)
        mock_request.url.query = ""

        sut = MediaResourceGateway(
            event_manager=mock_event_manager,
            async_client=mock_async_client,
            circuit_breaker=mock_circuit_breaker,
            header_factory=mock_header_factory,
        )

        return (
            sut,
            mock_event_manager,
            mock_circuit_breaker,
            mock_header_factory,
            mock_request,
        )

    @mark.asyncio
    async def test_get_notifies_request_init_before_upstream_call(
        self,
        mock_dependencies: MockDependencies,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
        faker: Faker,
    ) -> None:
        (
            sut,
            mock_event_manager,
            mock_circuit_breaker,
            mock_header_factory,
            mock_request,
        ) = mock_dependencies
        upstream_headers = {faker.word(): faker.word()}
        mock_header_factory.create.return_value = upstream_headers
        headers = make_forward_media_resource_request_headers()

        mock_circuit_breaker.call.return_value = HttpxResponse(status_code=200)

        await sut.get(request=mock_request, headers=headers)

        notified_event = mock_event_manager.notify.call_args_list[0][0][0]
        assert isinstance(notified_event, RequestInit)
        assert notified_event.headers is headers
        assert notified_event.upstream_headers is upstream_headers

    @mark.asyncio
    async def test_get_notifies_request_finished_on_success(
        self,
        mock_dependencies: MockDependencies,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
        faker: Faker,
    ) -> None:
        (
            sut,
            mock_event_manager,
            mock_circuit_breaker,
            mock_header_factory,
            mock_request,
        ) = mock_dependencies
        upstream_headers = {faker.word(): faker.word()}
        mock_header_factory.create.return_value = upstream_headers
        mock_circuit_breaker.call.return_value = HttpxResponse(status_code=200)

        await sut.get(
            request=mock_request, headers=make_forward_media_resource_request_headers()
        )

        notified_event = mock_event_manager.notify.call_args_list[-1][0][0]
        assert isinstance(notified_event, RequestFinished)
        assert notified_event.status_code == 200

    @mark.asyncio
    async def test_get_returns_upstream_response(
        self,
        mock_dependencies: MockDependencies,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
    ) -> None:
        (
            sut,
            _,
            mock_circuit_breaker,
            mock_header_factory,
            mock_request,
        ) = mock_dependencies
        mock_header_factory.create.return_value = {}
        mock_circuit_breaker.call.return_value = HttpxResponse(
            status_code=200, content=b"Hello World"
        )

        result = await sut.get(
            request=mock_request, headers=make_forward_media_resource_request_headers()
        )

        assert result.status_code == 200
        assert result.body == b"Hello World"

    @mark.asyncio
    async def test_get_uses_correlation_id_as_trace_id_when_present(
        self,
        mock_dependencies: MockDependencies,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
        faker: Faker,
    ) -> None:
        (
            sut,
            mock_event_manager,
            mock_circuit_breaker,
            mock_header_factory,
            mock_request,
        ) = mock_dependencies
        correlation_id = str(faker.uuid4())
        mock_header_factory.create.return_value = {}
        mock_circuit_breaker.call.return_value = HttpxResponse(status_code=200)

        await sut.get(
            request=mock_request,
            headers=make_forward_media_resource_request_headers(
                correlation_id=correlation_id
            ),
        )

        notified_event = mock_event_manager.notify.call_args_list[0][0][0]
        assert isinstance(notified_event, RequestInit)
        assert notified_event.trace_id == correlation_id

    @mark.asyncio
    async def test_get_on_timeout_notifies_request_timeout_and_raises_504(
        self,
        mock_dependencies: MockDependencies,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
    ) -> None:
        (
            sut,
            mock_event_manager,
            mock_circuit_breaker,
            mock_header_factory,
            mock_request,
        ) = mock_dependencies
        mock_header_factory.create.return_value = {}
        mock_circuit_breaker.call.side_effect = TimeoutException("Timed out")

        with raises(HTTPException) as exc_info:
            await sut.get(
                request=mock_request,
                headers=make_forward_media_resource_request_headers(),
            )

        assert exc_info.value.status_code == 504

        notified_event = mock_event_manager.notify.call_args_list[-1][0][0]
        assert isinstance(notified_event, RequestTimeout)
        assert notified_event.status_code == 408

    @mark.asyncio
    async def test_get_on_circuit_open_notifies_request_timeout_and_raises_502(
        self,
        mock_dependencies: MockDependencies,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
    ) -> None:
        (
            sut,
            mock_event_manager,
            mock_circuit_breaker,
            mock_header_factory,
            mock_request,
        ) = mock_dependencies
        mock_header_factory.create.return_value = {}
        mock_circuit_breaker.call.side_effect = CircuitOpenException()

        with raises(HTTPException) as exc_info:
            await sut.get(
                request=mock_request,
                headers=make_forward_media_resource_request_headers(),
            )

        assert exc_info.value.status_code == 502

        notified_event = mock_event_manager.notify.call_args_list[-1][0][0]
        assert isinstance(notified_event, RequestTimeout)

    @mark.asyncio
    async def test_get_filters_excluded_response_headers(
        self,
        mock_dependencies: MockDependencies,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
    ) -> None:
        (
            sut,
            _,
            mock_circuit_breaker,
            mock_header_factory,
            mock_request,
        ) = mock_dependencies
        mock_header_factory.create.return_value = {}
        mock_circuit_breaker.call.return_value = HttpxResponse(
            status_code=200,
            headers={
                "content-type": "application/json",
                "server": "nginx",
                "set-cookie": "session=abc",
                "transfer-encoding": "chunked",
            },
        )

        result = await sut.get(
            request=mock_request, headers=make_forward_media_resource_request_headers()
        )

        assert "content-type" in result.headers
        assert "server" not in result.headers
        assert "set-cookie" not in result.headers
        assert "transfer-encoding" not in result.headers

    @mark.asyncio
    async def test_get_delegates_to_header_factory_with_request_headers(
        self,
        mock_dependencies: MockDependencies,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
    ) -> None:
        (
            sut,
            _,
            mock_circuit_breaker,
            mock_header_factory,
            mock_request,
        ) = mock_dependencies
        mock_header_factory.create.return_value = {}
        mock_circuit_breaker.call.return_value = HttpxResponse(status_code=200)
        headers = make_forward_media_resource_request_headers()

        await sut.get(request=mock_request, headers=headers)

        mock_header_factory.create.assert_called_once_with(headers)
