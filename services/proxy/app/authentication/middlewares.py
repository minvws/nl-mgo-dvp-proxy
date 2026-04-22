from typing import Annotated
from fastapi import Body, Depends, HTTPException
from pydantic import ValidationError
from starlette.status import HTTP_400_BAD_REQUEST

from app.authentication.models import (
    GetStateRequest,
    OAuthRefreshRequest,
    ParsedGetStateRequest,
    ParsedOAuthRefreshRequest,
)
from app.security.dva_target.middlewares import parsed_dva_target_url


def parsed_oauth_getstate_request(
    request: Annotated[GetStateRequest, Body(...)],
) -> ParsedGetStateRequest:
    try:
        return ParsedGetStateRequest(
            auth_endpoint_url=parsed_dva_target_url(
                dva_target=request.auth_endpoint_jwe
            ),
            token_endpoint_url=parsed_dva_target_url(
                dva_target=request.token_endpoint_jwe
            ),
            medmij_scope=request.medmij_scope,
            client_target_url=request.client_target_url,
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=e.errors(include_url=False),
        )


def parsed_oauth_refresh_request(
    request: Annotated[OAuthRefreshRequest, Depends()],
) -> ParsedOAuthRefreshRequest:
    try:
        return ParsedOAuthRefreshRequest(
            token_endpoint_url=parsed_dva_target_url(
                dva_target=request.token_endpoint_jwe
            ),
            refresh_token=request.refresh_token,
            correlation_id=request.correlation_id,
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=e.errors(include_url=False),
        )
