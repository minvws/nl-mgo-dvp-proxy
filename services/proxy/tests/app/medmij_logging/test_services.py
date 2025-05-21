import json

import inject
import pytest
from faker import Faker
from pytest import CaptureFixture

from app.medmij_logging.enums import EventType
from app.medmij_logging.schemas import EventData, LogMessage
from app.medmij_logging.services import (
    MedMijLogger,
    ServerIdentifier,
    WWWAuthenticateErrorContext,
    WWWAuthenticateParser,
)
from tests.utils import clear_bindings, configure_bindings


class TestMedmijLogger:
    def test_medmij_logger_writes_log_to_stdout(
        self,
        capfd: CaptureFixture[str],
        faker: Faker,
    ) -> None:
        configure_bindings()

        event_type = faker.random_element(list(EventType))
        event_location = faker.hostname()
        datetime = faker.date_time()
        session_id = str(faker.uuid4())
        trace_id = str(faker.uuid4())

        medmij_logger = inject.instance(MedMijLogger)
        medmij_logger.log(
            LogMessage(
                event=EventData(
                    type=event_type,
                    location=event_location,
                    datetime=datetime,
                    session_id=session_id,
                    trace_id=trace_id,
                ),
            ),
        )

        expected_log_message = json.dumps(
            {
                "message": "medmij",
                "log_message": {
                    "event": {
                        "type": event_type.value,
                        "location": event_location,
                        "datetime": datetime.strftime("%Y-%m-%dT%H:%M:%S.%f"),
                        "session_id": session_id,
                        "trace_id": trace_id,
                    }
                },
            }
        )

        assert expected_log_message in capfd.readouterr().out

        clear_bindings()


class TestServerIdentifier:
    def test_get_server_id_for_uri_with_valid_uri(self) -> None:
        uri = "http://example.com"
        expected_server_id = "example.com"
        assert ServerIdentifier.get_server_id_for_uri(uri) == expected_server_id

    def test_get_server_id_for_uri_with_subdomain(self) -> None:
        uri = "http://sub.example.com"
        expected_server_id = "sub.example.com"
        assert ServerIdentifier.get_server_id_for_uri(uri) == expected_server_id

    def test_get_server_id_for_uri_with_invalid_uri_missing_hostname(self) -> None:
        uri = "http:///path"
        with pytest.raises(
            ValueError, match="Invalid token server URI: missing hostname"
        ):
            ServerIdentifier.get_server_id_for_uri(uri)

    def test_get_server_id_can_handle_freaky_urls(self) -> None:
        uri = "http://as.dva.i.can.have.a.lot.of.subdomains.as.example.com:8080"
        expected_server_id = "as.dva.i.can.have.a.lot.of.subdomains.as.example.com"
        assert ServerIdentifier.get_server_id_for_uri(uri) == expected_server_id


class TestWWWAuthenticateParser:
    @pytest.mark.parametrize(
        "header, expected_error, expected_error_description",
        [
            ("", None, None),
            ('Bearer realm="example"', None, None),
            ('Bearer realm="example", error="invalid_token"', "invalid_token", None),
            (
                'Bearer realm="example", error="invalid_token", error_description="The access token expired"',
                "invalid_token",
                "The access token expired",
            ),
            (
                'Bearer realm="example", error="invalid_token", error_description="Token expired", error_uri="https://example.com/error", scope="openid profile"',
                "invalid_token",
                "Token expired",
            ),
            (
                """
                Bearer realm="example",
                 error="invalid_token",
                 error_description="Token expired",
                 error_uri="https://example.com/error",
                 scope="openid profile"
                """,
                "invalid_token",
                "Token expired",
            ),
            (
                'Bearer realm="example", ERROR="invalid_token", ERROR_DESCRIPTION="Token expired"',
                "invalid_token",
                "Token expired",
            ),
        ],
    )
    def test_parse_with_data_provider(
        self, header: str, expected_error: str, expected_error_description: str
    ) -> None:
        parser = WWWAuthenticateParser()

        result: WWWAuthenticateErrorContext = parser.parse(header)

        assert result.error == expected_error
        assert result.error_description == expected_error_description
