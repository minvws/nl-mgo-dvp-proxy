from datetime import datetime
from typing import Optional, Union

from pydantic import BaseModel

from .constants import DEFAULT_CLIENT_ID
from .enums import EventType, GrantType


class EventData(BaseModel):
    type: EventType
    location: str
    datetime: datetime
    session_id: str
    trace_id: str


class RequestData(BaseModel):
    id: str
    method: str
    client_id: str = DEFAULT_CLIENT_ID
    server_id: str
    uri: str


class ResponseData(BaseModel):
    id: str
    status: int


class ErrorData(BaseModel):
    code: str
    description: str


class RequestErrorData(ErrorData):
    request_id: str
    status: int


class TokenRequestData(RequestData):
    grant_type: GrantType
    initiated_by: str = "person"


class ResourceRequestData(RequestData):
    # Optional for now so the clients can implement this, should be mandatory in the future.
    provider_id: Optional[str]
    service_id: Optional[int]


class LogMessage(BaseModel):
    event: EventData


class RequestLogMessage(LogMessage):
    request: Union[RequestData, TokenRequestData, ResourceRequestData]


class ResponseLogMessage(LogMessage):
    response: ResponseData


class ErrorLogMessage(LogMessage):
    error: Union[ErrorData, RequestErrorData]


class ErrorResponseLogMessage(ErrorLogMessage):
    response: ResponseData
