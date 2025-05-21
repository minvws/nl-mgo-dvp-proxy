import uuid
from datetime import datetime, timedelta, timezone

from app.config.models import BaseUrl

from .enums import EventType, GrantType
from .schemas import (
    ErrorData,
    ErrorLogMessage,
    ErrorResponseLogMessage,
    EventData,
    LogMessage,
    RequestErrorData,
    RequestLogMessage,
    ResourceRequestData,
    ResponseData,
    ResponseLogMessage,
    TokenRequestData,
)


class LogMessageFactory:
    def __init__(self, base_url: BaseUrl) -> None:
        self.__base_url = base_url

    def __get_formatted_time(self) -> datetime:
        return datetime.now(tz=timezone(timedelta(hours=1)))

    def __create_event_data(
        self, type: EventType, session_id: str, trace_id: str
    ) -> EventData:
        return EventData(
            datetime=self.__get_formatted_time(),
            location=self.__base_url.host,
            session_id=session_id,
            trace_id=trace_id,
            type=type,
        )

    def send_token_request(
        self,
        session_id: str,
        trace_id: str,
        server_id: str,
        method: str,
        token_server_uri: str,
        grant_type: GrantType,
    ) -> LogMessage:
        return RequestLogMessage(
            event=self.__create_event_data(
                session_id=session_id,
                trace_id=trace_id,
                type=EventType.SEND_TOKEN_REQUEST,
            ),
            request=TokenRequestData(
                id=str(uuid.uuid4()),
                server_id=server_id,
                method=method,
                uri=token_server_uri,
                grant_type=grant_type,
                initiated_by="person",
            ),
        )

    def create_send_resource_request_message(
        self,
        session_id: str,
        trace_id: str,
        request_id: str,
        server_id: str,
        method: str,
        resource_server_uri: str,
        provider_id: str
        | None,  # optional for now to give clients time to implement required header
        service_id: int
        | None,  # optional for now to give clients time to implement required header
    ) -> LogMessage:
        return RequestLogMessage(
            event=self.__create_event_data(
                session_id=session_id,
                trace_id=trace_id,
                type=EventType.SEND_RESOURCE_REQUEST,
            ),
            request=ResourceRequestData(
                id=request_id,
                server_id=server_id,
                method=method,
                uri=resource_server_uri,
                provider_id=provider_id,
                service_id=service_id,
            ),
        )

    def create_receive_resource_response(
        self,
        session_id: str,
        trace_id: str,
        status_code: int,
        request_id: str = "00000000-0000-0000-0000-000000000000",
    ) -> ResponseLogMessage:
        return ResponseLogMessage(
            event=self.__create_event_data(
                session_id=session_id,
                trace_id=trace_id,
                type=EventType.RECEIVE_RESOURCE_REQUEST_ERROR,
            ),
            response=ResponseData(id=request_id, status=status_code),
        )

    def create_receive_resource_request_error(
        self,
        session_id: str,
        trace_id: str,
        status_code: int,
        description: str,
        error_code: str = "other",
        request_id: str = "00000000-0000-0000-0000-000000000000",
    ) -> ErrorLogMessage:
        return ErrorLogMessage(
            event=self.__create_event_data(
                session_id=session_id,
                trace_id=trace_id,
                type=EventType.RECEIVE_RESOURCE_ERROR_RESPONSE,
            ),
            error=RequestErrorData(
                # for oauth: the received error code, otherwise use 'other'
                code=error_code,
                description=description,
                request_id=request_id,
                status=status_code,
            ),
        )

    def create_receive_resource_error_response(
        self,
        session_id: str,
        trace_id: str,
        status_code: int,
        description: str,
        error_code: str = "other",
        request_id: str = "00000000-0000-0000-0000-000000000000",
    ) -> ErrorResponseLogMessage:
        return ErrorResponseLogMessage(
            event=self.__create_event_data(
                session_id=session_id,
                trace_id=trace_id,
                type=EventType.RECEIVE_RESOURCE_ERROR_RESPONSE,
            ),
            error=ErrorData(
                # for oauth: the received error code, otherwise use 'other'
                code=error_code,
                description=description,
            ),
            response=ResponseData(id=request_id, status=status_code),
        )
