from datetime import datetime
from uuid import UUID

import pytest
from freezegun import freeze_time
from pydantic import AnyHttpUrl

from app.config.models import BaseUrl
from app.medmij_logging.enums import EventType, GrantType
from app.medmij_logging.factories import LogMessageFactory
from app.medmij_logging.schemas import (
    ErrorLogMessage,
    EventData,
    RequestErrorData,
    RequestLogMessage,
    TokenRequestData,
)


@pytest.fixture
def base_url() -> BaseUrl:
    return BaseUrl(AnyHttpUrl("https://dva.test.mgo.irealisatie.nl/"))


@pytest.fixture
def log_message_factory(base_url: BaseUrl) -> LogMessageFactory:
    return LogMessageFactory(base_url)


@freeze_time("2024-12-18T15:51:40.425499")
def test_send_token_request(log_message_factory: LogMessageFactory) -> None:
    session_id = "session123"
    trace_id = "trace456"
    server_id = "server789"
    method = "POST"
    token_server_uri = "http://token-server.com"
    grant_type = GrantType.AUTHORIZATION_CODE

    expected_event_data = EventData(
        datetime=datetime.fromisoformat("2024-12-18T16:51:40.425499+01:00"),
        location="dva.test.mgo.irealisatie.nl",
        session_id=session_id,
        trace_id=trace_id,
        type=EventType.SEND_TOKEN_REQUEST,
    )

    log_message = log_message_factory.send_token_request(
        session_id=session_id,
        trace_id=trace_id,
        server_id=server_id,
        method=method,
        token_server_uri=token_server_uri,
        grant_type=grant_type,
    )

    assert isinstance(log_message, RequestLogMessage)
    assert log_message.event == expected_event_data
    assert isinstance(log_message.request, TokenRequestData)
    assert log_message.request.server_id == server_id
    assert log_message.request.method == method
    assert log_message.request.uri == token_server_uri
    assert log_message.request.grant_type == grant_type
    assert isinstance(UUID(log_message.request.id), UUID)


def test_it_can_create_a_receive_resource_error_message(
    log_message_factory: LogMessageFactory,
) -> None:
    expected_status_code = 404
    request_id = "request123"

    log_message = log_message_factory.create_receive_resource_request_error(
        request_id=request_id,
        trace_id="trace456",
        session_id="session123",
        status_code=expected_status_code,
        description="invalid_request",
    )

    assert isinstance(log_message, ErrorLogMessage)
    assert isinstance(log_message.error, RequestErrorData)
    assert log_message.error.code == "other"
    assert log_message.error.description == "invalid_request"
    assert log_message.error.request_id == request_id
    assert log_message.error.status == expected_status_code
