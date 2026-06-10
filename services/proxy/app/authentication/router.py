from typing import Annotated, Any, Dict

from fastapi import APIRouter, Depends, Response
from fastapi.responses import JSONResponse

from app.utils import resolve_instance

from .exceptions import AuthorizationHttpException
from .middleware import (
    parsed_oauth_getstate_request,
    parsed_oauth_refresh_request,
)
from .schemas import (
    AuthorizationAccessTokenCallbackRedirectResponse,
    GetStateResponse,
    OAuthCallbackRequest,
    ParsedGetStateRequest,
    ParsedOAuthRefreshRequest,
)
from .services import (
    MedMijAuthRequestUrlDirector,
    MedMijOauthTokenService,
    StateService,
)
from .validation import MedMijOAuthCallbackRequestValidator

router = APIRouter(
    tags=["authentication"],
)


@router.post("/getstate")
async def get_state(
    request: Annotated[ParsedGetStateRequest, Depends(parsed_oauth_getstate_request)],
    director: MedMijAuthRequestUrlDirector = resolve_instance(
        MedMijAuthRequestUrlDirector
    ),
) -> GetStateResponse:
    """
    Generates an URL for the authorization request.

    Responses:
        200: Authorization URL successfully generated.
        400: Parsing DVA endpoint failed.
        422: Request validation failed.
        500: Internal server error.
    """

    url: str = director.build_authorization_request_url(
        authorization_server_url=request.auth_endpoint_url,
        token_endpoint_url=request.token_endpoint_url,
        client_target_url=request.payload.client_target_url,
        scope=request.payload.medmij_scope,
    )

    return GetStateResponse(url_to_request=url)


@router.get("/auth/callback")
async def handle_oauth_callback(
    request: Annotated[OAuthCallbackRequest, Depends()],
    state_service: StateService = resolve_instance(StateService),
    token_service: MedMijOauthTokenService = resolve_instance(
        cls=MedMijOauthTokenService
    ),
    validator: MedMijOAuthCallbackRequestValidator = resolve_instance(
        MedMijOAuthCallbackRequestValidator
    ),
) -> Response:
    """
    Handles the OAuth callback from the authorization server.

    Responses:
        307: Redirect to client with access token.
        403: Authorization failed.
        422: Request validation failed.
        500: Internal server error.

    Raises:
        AuthorizationHttpException: If the authorization server returns an error.
        RequestValidationException: If the request validation fails.
        MedMijOAuthException: For any other internal authorization-related errors.
    """

    # Extra query parameter validation. Exceptions are handled by the validation_exception_handler
    validator.validate_query_params(
        error=request.error, code=request.code, state=request.state
    )

    # The Authorization server may return with an error
    if request.error:
        error_detail: Dict[str, Any | None] = {
            "error": request.error,
            "error_description": request.error_description or None,
            "error_uri": request.error_uri or None,
        }
        raise AuthorizationHttpException(status_code=401, detail=error_detail)

    # Verify the state token. Exceptions are handled by the medmij_exception_handler
    state_dto = state_service.get_state_dto(token=str(request.state))

    # Request an access token using the authorization code
    access_token = await token_service.retrieve_access_token(
        token_server_uri=str(state_dto.token_endpoint_url),
        code=str(request.code),
        correlation_id=str(state_dto.correlation_id),
    )

    # Create the access token callback redirect URL which is redirected to the clients to store the token data.
    url: str = token_service.create_access_token_retrieval_redirect_url(
        client_target_url=str(state_dto.client_target_url),
        access_token_dto=access_token,
        correlation_id=str(state_dto.correlation_id),
    )

    return AuthorizationAccessTokenCallbackRedirectResponse(redirect_url=url)


@router.get("/auth/refresh")
async def handle_auth_refresh(
    request: Annotated[
        ParsedOAuthRefreshRequest, Depends(parsed_oauth_refresh_request)
    ],
    token_service: MedMijOauthTokenService = resolve_instance(
        cls=MedMijOauthTokenService
    ),
) -> Response:
    """
    Handles the token refresh from the token server.

    Responses:
        200: Return new access token data.
        400: Parsing DVA endpoint failed.
        403: Authorization failed.
        422: Request validation failed.
        500: Internal server error.

    Raises:
        AuthorizationHttpException: If the authorization server returns an error.
        RequestValidationException: If the request validation fails.
        MedMijOAuthException: For any other internal authorization-related errors.
    """
    access_token = await token_service.refresh_access_token(
        token_server_uri=str(request.token_endpoint_url),
        refresh_token=str(request.payload.refresh_token),
        correlation_id=str(request.payload.correlation_id),
    )

    return JSONResponse(content=access_token.model_dump())
