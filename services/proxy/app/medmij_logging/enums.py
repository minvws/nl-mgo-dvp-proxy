from enum import Enum


class EventType(str, Enum):
    SEND_TOKEN_REQUEST = "send_token_request"
    SEND_RESOURCE_REQUEST = "send_resource_request"
    RECEIVE_RESOURCE_REQUEST_ERROR = "receive_resource_request_error"
    RECEIVE_RESOURCE_ERROR_RESPONSE = "receive_resource_error_response"


class GrantType(str, Enum):
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
