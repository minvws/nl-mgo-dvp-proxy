from faker import Faker
from pytest import fixture
from pytest_mock import MockerFixture, MockType

from app.forwarding.constants import MEDMIJ_REQUEST_ID_HEADER
from app.forwarding.events import RequestFinished, RequestInit, RequestTimeout
from app.medmij_logging.constants import WWW_AUTHENTICATE_HEADER
from app.medmij_logging.factories import LogMessageFactory
from app.medmij_logging.listeners import (
    CreateMedMijLogEntryForRequestFinished,
    CreateMedMijLogEntryForRequestInit,
    CreateMedMijLogEntryForRequestTimeout,
)
from app.medmij_logging.services import MedMijLogger, WWWAuthenticateParser


@fixture
def mock_log_message_factory(mocker: MockerFixture) -> MockType:
    mock_log_message_factory: MockType = mocker.Mock(spec=LogMessageFactory)

    return mock_log_message_factory


@fixture
def mock_medmij_logger(mocker: MockerFixture) -> MockType:
    mock_medmij_logger: MockType = mocker.Mock(spec=MedMijLogger)

    return mock_medmij_logger


@fixture
def mock_www_authenticate_parser(mocker: MockerFixture) -> MockType:
    mock_www_authenticate_parser: MockType = mocker.Mock(spec=WWWAuthenticateParser)

    return mock_www_authenticate_parser


class TestCreateMedMijLogEntryForRequestInit:
    def test_handle_logs_send_resource_request_message(
        self,
        mock_log_message_factory: MockType,
        mock_medmij_logger: MockType,
        mock_www_authenticate_parser: MockType,
        mocker: MockerFixture,
        faker: Faker,
    ) -> None:
        sut = CreateMedMijLogEntryForRequestInit(
            log_message_factory=mock_log_message_factory,
            medmij_logger=mock_medmij_logger,
            www_authenticate_parser=mock_www_authenticate_parser,
        )
        request_id = faker.uuid4()
        event = RequestInit(
            request=mocker.Mock(method="GET"),
            headers=mocker.Mock(
                media_resource_url="https://media.example.org/image.jpg",
                healthcare_provider_id="provider-123",
                data_service_id=42,
            ),
            upstream_headers={MEDMIJ_REQUEST_ID_HEADER: request_id},
            trace_id=faker.uuid4(),
        )

        sut.handle(event)

        mock_log_message_factory.create_send_resource_request_message.assert_called_once()
        call_kwargs = mock_log_message_factory.create_send_resource_request_message.call_args.kwargs
        assert call_kwargs["trace_id"] == event.trace_id
        assert call_kwargs["request_id"] == request_id
        assert call_kwargs["server_id"] == "media.example.org"
        assert call_kwargs["method"] == "GET"
        assert (
            call_kwargs["resource_server_uri"] == "https://media.example.org/image.jpg"
        )
        assert call_kwargs["provider_id"] == "provider-123"
        assert call_kwargs["service_id"] == 42

        mock_medmij_logger.log.assert_called_once_with(
            mock_log_message_factory.create_send_resource_request_message.return_value
        )

    def test_handle_falls_back_to_generated_request_id_when_header_absent(
        self,
        mock_log_message_factory: MockType,
        mock_medmij_logger: MockType,
        mock_www_authenticate_parser: MockType,
        mocker: MockerFixture,
        faker: Faker,
    ) -> None:
        sut = CreateMedMijLogEntryForRequestInit(
            log_message_factory=mock_log_message_factory,
            medmij_logger=mock_medmij_logger,
            www_authenticate_parser=mock_www_authenticate_parser,
        )
        event = RequestInit(
            request=mocker.Mock(method="GET"),
            headers=mocker.Mock(
                media_resource_url="https://media.example.org/image.jpg",
                healthcare_provider_id=None,
                data_service_id=None,
            ),
            upstream_headers={},
            trace_id=faker.uuid4(),
        )

        sut.handle(event)

        call_kwargs = mock_log_message_factory.create_send_resource_request_message.call_args.kwargs
        assert call_kwargs["request_id"] != ""


class TestCreateMedMijLogEntryForRequestFinished:
    def test_handle_logs_success_response_for_2xx_status(
        self,
        mock_log_message_factory: MockType,
        mock_medmij_logger: MockType,
        mock_www_authenticate_parser: MockType,
        faker: Faker,
    ) -> None:
        sut = CreateMedMijLogEntryForRequestFinished(
            log_message_factory=mock_log_message_factory,
            medmij_logger=mock_medmij_logger,
            www_authenticate_parser=mock_www_authenticate_parser,
        )
        request_id = faker.uuid4()
        event = RequestFinished(
            upstream_headers={MEDMIJ_REQUEST_ID_HEADER: request_id},
            trace_id=faker.uuid4(),
            status_code=200,
            response_headers={},
        )

        sut.handle(event)

        mock_log_message_factory.create_receive_resource_response.assert_called_once()
        call_kwargs = (
            mock_log_message_factory.create_receive_resource_response.call_args.kwargs
        )
        assert call_kwargs["trace_id"] == event.trace_id
        assert call_kwargs["request_id"] == request_id
        assert call_kwargs["status_code"] == 200

        mock_log_message_factory.create_receive_resource_error_response.assert_not_called()
        mock_medmij_logger.log.assert_called_once_with(
            mock_log_message_factory.create_receive_resource_response.return_value
        )

    def test_handle_logs_error_response_for_4xx_status_without_www_authenticate(
        self,
        mock_log_message_factory: MockType,
        mock_medmij_logger: MockType,
        mock_www_authenticate_parser: MockType,
        faker: Faker,
    ) -> None:
        sut = CreateMedMijLogEntryForRequestFinished(
            log_message_factory=mock_log_message_factory,
            medmij_logger=mock_medmij_logger,
            www_authenticate_parser=mock_www_authenticate_parser,
        )
        event = RequestFinished(
            upstream_headers={MEDMIJ_REQUEST_ID_HEADER: faker.uuid4()},
            trace_id=faker.uuid4(),
            status_code=404,
            response_headers={},
        )

        sut.handle(event)

        mock_log_message_factory.create_receive_resource_response.assert_not_called()
        mock_log_message_factory.create_receive_resource_error_response.assert_called_once()
        call_kwargs = mock_log_message_factory.create_receive_resource_error_response.call_args.kwargs
        assert call_kwargs["status_code"] == 404
        assert call_kwargs["error_code"] == "other"
        assert call_kwargs["description"] == "unspecified error occurred"

    def test_handle_logs_timeout_error_for_408_status(
        self,
        mock_log_message_factory: MockType,
        mock_medmij_logger: MockType,
        mock_www_authenticate_parser: MockType,
        faker: Faker,
    ) -> None:
        sut = CreateMedMijLogEntryForRequestFinished(
            log_message_factory=mock_log_message_factory,
            medmij_logger=mock_medmij_logger,
            www_authenticate_parser=mock_www_authenticate_parser,
        )
        event = RequestFinished(
            upstream_headers={},
            trace_id=faker.uuid4(),
            status_code=408,
            response_headers={},
        )

        sut.handle(event)

        call_kwargs = mock_log_message_factory.create_receive_resource_error_response.call_args.kwargs
        assert call_kwargs["error_code"] == "temporarily_unavailable"
        assert call_kwargs["description"] == "request timed out"

    def test_handle_parses_www_authenticate_header_for_4xx_error(
        self,
        mock_log_message_factory: MockType,
        mock_medmij_logger: MockType,
        mock_www_authenticate_parser: MockType,
        faker: Faker,
    ) -> None:
        sut = CreateMedMijLogEntryForRequestFinished(
            log_message_factory=mock_log_message_factory,
            medmij_logger=mock_medmij_logger,
            www_authenticate_parser=mock_www_authenticate_parser,
        )
        www_authenticate_value = (
            'Bearer error="invalid_token", error_description="Token expired"'
        )
        mock_www_authenticate_parser.parse.return_value.error = "invalid_token"
        mock_www_authenticate_parser.parse.return_value.error_description = (
            "Token expired"
        )

        event = RequestFinished(
            upstream_headers={},
            trace_id=faker.uuid4(),
            status_code=401,
            response_headers={WWW_AUTHENTICATE_HEADER: www_authenticate_value},
        )

        sut.handle(event)

        mock_www_authenticate_parser.parse.assert_called_once_with(
            www_authenticate_value
        )

        call_kwargs = mock_log_message_factory.create_receive_resource_error_response.call_args.kwargs
        assert call_kwargs["error_code"] == "invalid_token"
        assert call_kwargs["description"] == "Token expired"

    def test_handle_omits_error_fields_when_www_authenticate_has_no_error(
        self,
        mock_log_message_factory: MockType,
        mock_medmij_logger: MockType,
        mock_www_authenticate_parser: MockType,
        faker: Faker,
    ) -> None:
        sut = CreateMedMijLogEntryForRequestFinished(
            log_message_factory=mock_log_message_factory,
            medmij_logger=mock_medmij_logger,
            www_authenticate_parser=mock_www_authenticate_parser,
        )
        mock_www_authenticate_parser.parse.return_value.error = None
        mock_www_authenticate_parser.parse.return_value.error_description = None

        event = RequestFinished(
            upstream_headers={},
            trace_id=faker.uuid4(),
            status_code=401,
            response_headers={WWW_AUTHENTICATE_HEADER: "Bearer"},
        )

        sut.handle(event)

        call_kwargs = mock_log_message_factory.create_receive_resource_error_response.call_args.kwargs
        assert "error_code" not in call_kwargs
        assert "description" not in call_kwargs

    def test_handle_falls_back_to_generated_request_id_when_header_absent(
        self,
        mock_log_message_factory: MockType,
        mock_medmij_logger: MockType,
        mock_www_authenticate_parser: MockType,
        faker: Faker,
    ) -> None:
        sut = CreateMedMijLogEntryForRequestFinished(
            log_message_factory=mock_log_message_factory,
            medmij_logger=mock_medmij_logger,
            www_authenticate_parser=mock_www_authenticate_parser,
        )
        event = RequestFinished(
            upstream_headers={},
            trace_id=faker.uuid4(),
            status_code=200,
            response_headers={},
        )

        sut.handle(event)

        call_kwargs = (
            mock_log_message_factory.create_receive_resource_response.call_args.kwargs
        )
        assert call_kwargs["request_id"] != ""


class TestCreateMedMijLogEntryForRequestTimeout:
    def test_handle_logs_timeout_error_response(
        self,
        mock_log_message_factory: MockType,
        mock_medmij_logger: MockType,
        mock_www_authenticate_parser: MockType,
        faker: Faker,
    ) -> None:
        sut = CreateMedMijLogEntryForRequestTimeout(
            log_message_factory=mock_log_message_factory,
            medmij_logger=mock_medmij_logger,
            www_authenticate_parser=mock_www_authenticate_parser,
        )
        request_id = faker.uuid4()
        event = RequestTimeout(
            upstream_headers={MEDMIJ_REQUEST_ID_HEADER: request_id},
            trace_id=faker.uuid4(),
            status_code=408,
        )

        sut.handle(event)

        mock_log_message_factory.create_receive_resource_error_response.assert_called_once()
        call_kwargs = mock_log_message_factory.create_receive_resource_error_response.call_args.kwargs
        assert call_kwargs["trace_id"] == event.trace_id
        assert call_kwargs["request_id"] == request_id
        assert call_kwargs["status_code"] == 408
        assert call_kwargs["error_code"] == "temporarily_unavailable"
        assert call_kwargs["description"] == "request timed out"

        mock_medmij_logger.log.assert_called_once_with(
            mock_log_message_factory.create_receive_resource_error_response.return_value
        )

    def test_handle_falls_back_to_generated_request_id_when_header_absent(
        self,
        mock_log_message_factory: MockType,
        mock_medmij_logger: MockType,
        mock_www_authenticate_parser: MockType,
        faker: Faker,
    ) -> None:
        sut = CreateMedMijLogEntryForRequestTimeout(
            log_message_factory=mock_log_message_factory,
            medmij_logger=mock_medmij_logger,
            www_authenticate_parser=mock_www_authenticate_parser,
        )
        event = RequestTimeout(
            upstream_headers={},
            trace_id=faker.uuid4(),
            status_code=408,
        )

        sut.handle(event)

        call_kwargs = mock_log_message_factory.create_receive_resource_error_response.call_args.kwargs
        assert call_kwargs["request_id"] != ""
