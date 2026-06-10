from typing import Annotated

from fastapi import Body, Depends

from app.authentication.schemas import (
    GetStateRequest,
    OAuthRefreshRequest,
    ParsedGetStateRequest,
    ParsedOAuthRefreshRequest,
)
from app.security.dva_target.services import (
    DvaTargetAssertionParser,
)
from app.utils import resolve_instance


def parsed_oauth_getstate_request(
    payload: Annotated[GetStateRequest, Body()],
    dva_target_assertion_parser: DvaTargetAssertionParser = resolve_instance(
        DvaTargetAssertionParser
    ),
) -> ParsedGetStateRequest:
    auth_endpoint_url = dva_target_assertion_parser.parse(
        serialized_jwe=payload.auth_endpoint_jwe,
        error_context={"field": "authorization_server_url"},
    )
    token_endpoint_url = dva_target_assertion_parser.parse(
        serialized_jwe=payload.token_endpoint_jwe,
        error_context={"field": "token_endpoint_url"},
    )

    return ParsedGetStateRequest(
        payload=payload,
        auth_endpoint_url=auth_endpoint_url,
        token_endpoint_url=token_endpoint_url,
    )


def parsed_oauth_refresh_request(
    payload: Annotated[OAuthRefreshRequest, Depends()],
    dva_target_assertion_parser: DvaTargetAssertionParser = resolve_instance(
        DvaTargetAssertionParser
    ),
) -> ParsedOAuthRefreshRequest:
    token_endpoint_url = dva_target_assertion_parser.parse(
        serialized_jwe=payload.token_endpoint_jwe,
        error_context={"field": "token_endpoint_url"},
    )

    return ParsedOAuthRefreshRequest(
        payload=payload,
        token_endpoint_url=token_endpoint_url,
    )
