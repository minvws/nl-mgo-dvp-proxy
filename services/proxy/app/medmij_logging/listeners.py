from abc import ABC
from uuid import uuid4

from inject import autoparams

from app.forwarding.constants import MEDMIJ_REQUEST_ID_HEADER
from app.forwarding.events import RequestFinished, RequestInit, RequestTimeout
from app.medmij_logging.constants import WWW_AUTHENTICATE_HEADER

from .factories import LogMessageFactory
from .services import MedMijLogger, ServerIdentifier, WWWAuthenticateParser


class BaseMedMijLogEntryListener(ABC):
    @autoparams()
    def __init__(
        self,
        log_message_factory: LogMessageFactory,
        medmij_logger: MedMijLogger,
        www_authenticate_parser: WWWAuthenticateParser,
    ) -> None:
        self._log_message_factory: LogMessageFactory = log_message_factory
        self._medmij_logger: MedMijLogger = medmij_logger
        self._www_authenticate_parser: WWWAuthenticateParser = www_authenticate_parser


class CreateMedMijLogEntryForRequestInit(BaseMedMijLogEntryListener):
    def handle(self, event: RequestInit) -> None:
        self._medmij_logger.log(
            self._log_message_factory.create_send_resource_request_message(
                session_id=uuid4().hex,
                trace_id=event.trace_id,
                request_id=event.upstream_headers.get(
                    MEDMIJ_REQUEST_ID_HEADER, uuid4().hex
                ),
                server_id=ServerIdentifier.get_server_id_for_uri(
                    event.headers.media_resource_url
                ),
                method=event.request.method,
                resource_server_uri=event.headers.media_resource_url,
                provider_id=event.headers.healthcare_provider_id,
                service_id=event.headers.data_service_id,
            )
        )


class CreateMedMijLogEntryForRequestFinished(BaseMedMijLogEntryListener):
    def handle(self, event: RequestFinished) -> None:
        log_message_params = {
            "session_id": uuid4().hex,
            "trace_id": event.trace_id,
            "request_id": event.upstream_headers.get(
                MEDMIJ_REQUEST_ID_HEADER, uuid4().hex
            ),
            "status_code": event.status_code,
        }

        if event.status_code < 400:
            self._medmij_logger.log(
                self._log_message_factory.create_receive_resource_response(
                    **log_message_params,
                )
            )

            return

        www_authenticate_header = event.response_headers.get(WWW_AUTHENTICATE_HEADER)

        if event.status_code == 408:
            log_message_params.update(
                {
                    "error_code": "temporarily_unavailable",
                    "description": "request timed out",
                }
            )
        elif www_authenticate_header:
            error_context = self._www_authenticate_parser.parse(www_authenticate_header)

            if error_context.error:
                log_message_params["error_code"] = error_context.error

            if error_context.error_description:
                log_message_params["description"] = error_context.error_description
        else:
            log_message_params.update(
                {
                    "error_code": "other",
                    "description": "unspecified error occurred",
                }
            )

        self._medmij_logger.log(
            self._log_message_factory.create_receive_resource_error_response(
                **log_message_params,
            )
        )


class CreateMedMijLogEntryForRequestTimeout(BaseMedMijLogEntryListener):
    def handle(self, event: RequestTimeout) -> None:
        self._medmij_logger.log(
            self._log_message_factory.create_receive_resource_error_response(
                session_id=uuid4().hex,
                trace_id=event.trace_id,
                request_id=event.upstream_headers.get(
                    MEDMIJ_REQUEST_ID_HEADER, uuid4().hex
                ),
                status_code=event.status_code,
                error_code="temporarily_unavailable",
                description="request timed out",
            )
        )
