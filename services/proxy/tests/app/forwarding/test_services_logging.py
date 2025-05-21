from logging import Logger
from typing import Generator

import pytest
from fastapi import Request
from httpx import Response as HttpxResponse
from httpx import TimeoutException
from inject import Binder
from pydantic import AnyHttpUrl
from pytest_mock import MockerFixture

from app.circuitbreaker.models import CircuitOpenException
from app.circuitbreaker.services import CircuitBreakerService
from app.forwarding.schemas import ProxyHeaders
from app.forwarding.services import ForwardingService, RequestForwardingLogHandler
from app.forwarding.signing.services import DvaTargetVerifier
from app.medmij_logging.schemas import (
    ErrorData,
    ErrorLogMessage,
    ErrorResponseLogMessage,
    RequestErrorData,
    ResponseData,
)
from app.medmij_logging.services import MedMijLogger
from tests.utils import clear_bindings, configure_bindings


def make_www_authenticate_header(
    error: str | None, error_description: str | None
) -> str:
    www_authenticate_header = 'Bearer realm="example"'

    if error:
        www_authenticate_header += f', error="{error}"'

    if error_description:
        www_authenticate_header += f', error_description="{error_description}"'

    return www_authenticate_header


def make_forwarding_service(
    circuit_breaker: CircuitBreakerService, medmij_logger: MedMijLogger
) -> ForwardingService:
    forwarding_service: ForwardingService = ForwardingService(
        circuit_breaker=circuit_breaker,
        request_forwarding_log_handler=RequestForwardingLogHandler(
            medmij_logger=medmij_logger
        ),
    )

    return forwarding_service


@pytest.fixture(autouse=True)
def mock_dva_target_verifier(mocker: MockerFixture) -> Generator[None, None, None]:
    """Configure (and later clear) the dependency bindings automatically."""

    def bindings_override(binder: Binder) -> Binder:
        dva_target_verifier = mocker.Mock(DvaTargetVerifier)
        dva_target_verifier.verify = mocker.AsyncMock(side_effect=None)
        binder.bind(DvaTargetVerifier, dva_target_verifier)
        return binder

    configure_bindings(bindings_override=bindings_override)

    yield

    clear_bindings()


@pytest.fixture
def test_request(mocker: MockerFixture) -> Request:
    request = mocker.Mock(Request)
    request.method = "GET"
    request.url.path = "/resource"
    request.url.query = "param=value"
    return request  # type: ignore[no-any-return]


@pytest.fixture
def test_headers() -> ProxyHeaders:
    return ProxyHeaders(
        dva_target=AnyHttpUrl("https://mock_target"),
        x_mgo_provider_id="eenofanderezorgaanbieder",
        x_mgo_service_id=63,
        accept="application/fhir+json; fhirVersion=3.0",
    )


@pytest.fixture
def medmij_logger(mocker: MockerFixture) -> MedMijLogger:
    return MedMijLogger(logger=mocker.Mock(Logger))


@pytest.fixture
def medmij_logger_spy(
    mocker: MockerFixture, medmij_logger: MedMijLogger
) -> MockerFixture:
    return mocker.spy(medmij_logger, "log")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response_status_code, www_authenticate_header, expected_error, expected_error_description",
    [
        (
            400,
            make_www_authenticate_header(
                "invalid_request", "The request was malformed"
            ),
            "invalid_request",
            "The request was malformed",
        ),
        (
            401,
            make_www_authenticate_header(
                "invalid_token", "The access token is expired"
            ),
            "invalid_token",
            "The access token is expired",
        ),
        (
            403,
            make_www_authenticate_header(
                "insufficient_scope", "The scope was insufficient"
            ),
            "insufficient_scope",
            "The scope was insufficient",
        ),
    ],
)
async def test_it_logs_resource_request_error_with_provided_error_context(
    medmij_logger: MedMijLogger,
    medmij_logger_spy: MockerFixture,
    mocker: MockerFixture,
    test_request: Request,
    test_headers: ProxyHeaders,
    response_status_code: int,
    www_authenticate_header: str,
    expected_error: str,
    expected_error_description: str,
) -> None:
    circuit_breaker_mock = mocker.Mock(CircuitBreakerService)
    circuit_breaker_mock.call = mocker.AsyncMock(
        return_value=HttpxResponse(
            status_code=response_status_code,
            content="Hello world",
            headers={
                "WWW-Authenticate": www_authenticate_header,
            },
        )
    )

    service = make_forwarding_service(circuit_breaker_mock, medmij_logger)
    await service.get_resource(request=test_request, headers=test_headers)

    assert medmij_logger_spy.call_count == 2  # type: ignore[attr-defined]
    log_message = medmij_logger_spy.call_args[0][0]  # type: ignore[attr-defined]

    assert isinstance(log_message, ErrorLogMessage)
    assert isinstance(log_message.error, RequestErrorData)
    assert log_message.error.code == expected_error
    assert log_message.error.description == expected_error_description
    assert log_message.error.status == response_status_code
    assert log_message.error.request_id is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response_status_code, www_authenticate_header, expected_error, expected_error_description",
    [
        (400, None, "other", ""),
        (401, None, "other", ""),
        (403, None, "other", ""),
        (
            400,
            make_www_authenticate_header(None, None),
            "other",
            "",
        ),
        (
            400,
            make_www_authenticate_header("invalid_request", None),
            "invalid_request",
            "",
        ),
        (
            400,
            make_www_authenticate_header(None, "The request was malformed"),
            "other",
            "The request was malformed",
        ),
    ],
)
async def test_it_logs_resource_request_error_with_default_error_context(
    medmij_logger: MedMijLogger,
    medmij_logger_spy: MockerFixture,
    mocker: MockerFixture,
    test_request: Request,
    test_headers: ProxyHeaders,
    response_status_code: int,
    www_authenticate_header: str | None,
    expected_error: str,
    expected_error_description: str,
) -> None:
    circuit_breaker_mock = mocker.Mock(CircuitBreakerService)
    circuit_breaker_mock.call = mocker.AsyncMock(
        return_value=HttpxResponse(
            status_code=response_status_code,
            content="Hello world",
            headers={
                "WWW-Authenticate": www_authenticate_header,
            }
            if www_authenticate_header
            else {},
        )
    )

    service = make_forwarding_service(circuit_breaker_mock, medmij_logger)
    await service.get_resource(request=test_request, headers=test_headers)

    assert medmij_logger_spy.call_count == 2  # type: ignore[attr-defined]
    log_message = medmij_logger_spy.call_args[0][0]  # type: ignore[attr-defined]

    assert isinstance(log_message, ErrorLogMessage)
    assert isinstance(log_message.error, RequestErrorData)
    assert log_message.error.code == expected_error
    assert log_message.error.description == expected_error_description
    assert log_message.error.status == response_status_code
    assert log_message.error.request_id is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception_type",
    [TimeoutException, CircuitOpenException],
)
async def test_it_logs_resource_error_response_on_request_timeout(
    medmij_logger: MedMijLogger,
    medmij_logger_spy: MockerFixture,
    mocker: MockerFixture,
    test_request: Request,
    test_headers: ProxyHeaders,
    exception_type: type[Exception],
) -> None:
    circuit_breaker_mock = mocker.Mock(CircuitBreakerService)
    circuit_breaker_mock.call = mocker.AsyncMock(
        side_effect=exception_type("Request timed out")
    )

    with pytest.raises(Exception):
        service = make_forwarding_service(circuit_breaker_mock, medmij_logger)
        await service.get_resource(request=test_request, headers=test_headers)

    assert medmij_logger_spy.call_count == 2  # type: ignore[attr-defined]
    log_message = medmij_logger_spy.call_args[0][0]  # type: ignore[attr-defined]

    assert isinstance(log_message, ErrorResponseLogMessage)
    assert isinstance(log_message.error, ErrorData)
    assert isinstance(log_message.response, ResponseData)
    assert log_message.error.code == "temporarily_unavailable"
    assert log_message.error.description == "request timed out"
    assert log_message.response.status == 408
    assert log_message.response.id is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response_status_code",
    [404, 422, 500],
)
async def test_it_logs_resource_error_response_on_other_error_responses(
    medmij_logger: MedMijLogger,
    medmij_logger_spy: MockerFixture,
    mocker: MockerFixture,
    test_request: Request,
    test_headers: ProxyHeaders,
    response_status_code: int,
) -> None:
    circuit_breaker_mock = mocker.Mock(CircuitBreakerService)
    circuit_breaker_mock.call = mocker.AsyncMock(
        return_value=HttpxResponse(
            status_code=response_status_code,
            content="Hello world",
        )
    )

    service = make_forwarding_service(circuit_breaker_mock, medmij_logger)
    await service.get_resource(request=test_request, headers=test_headers)

    assert medmij_logger_spy.call_count == 2  # type: ignore[attr-defined]
    log_message = medmij_logger_spy.call_args[0][0]  # type: ignore[attr-defined]

    assert isinstance(log_message, ErrorResponseLogMessage)
    assert isinstance(log_message.error, ErrorData)
    assert isinstance(log_message.response, ResponseData)
    assert log_message.error.code == "other"
    assert log_message.error.description == ""
    assert log_message.response.status == response_status_code
    assert log_message.response.id is not None
