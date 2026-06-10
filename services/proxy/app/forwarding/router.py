from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from app.utils import resolve_instance

from .constants import FORWARD_URL_RESPONSE_HEADER
from .middleware import (
    validated_forward_media_resource_request_headers,
    validated_forwarding_request_headers,
)
from .schemas import (
    ForwardingRequestHeaders,
    ForwardMediaResourceRequestHeaders,
)
from .services import ForwardingService, MediaResourceGateway

router = APIRouter()


@router.get(
    path="/fhir/{path:path}",
    description="Forwards a request through the proxy towards a healthcare provider.",
    openapi_extra={
        "parameters": [
            {
                "name": "path",
                "in": "path",
                "description": "The relative path of the URL to hit on the healthcare provider (without forward slash).",
                "schema": {"type": "string"},
            }
        ],
        "responses": {
            200: {
                "description": "Successful response",
                "content": {"application/json+fhir": {"example": {}}},
                "headers": {
                    FORWARD_URL_RESPONSE_HEADER: {
                        "description": "Represents the URL that the proxy forwarded to.",
                        "schema": {"type": "string"},
                    },
                },
            },
        },
    },
)
async def forward_client_request(
    request: Request,
    headers: Annotated[
        ForwardingRequestHeaders, Depends(validated_forwarding_request_headers)
    ],
    path: str,
    forwarding_service: ForwardingService = resolve_instance(ForwardingService),
) -> Response:
    return await forwarding_service.get_resource(
        path=f"/fhir/{path}",
        request=request,
        headers=headers,
    )


@router.get(
    path="/gateway",
    description="This endpoint is intended as a proxy for a resource server containing media resources identified by the content attachment URL of a DocumentReference FHIR resource.",
    openapi_extra={
        "responses": {
            200: {
                "description": "Successful response containing the requested media resource.",
                "headers": {
                    FORWARD_URL_RESPONSE_HEADER: {
                        "description": "The upstream requested URL from which the media resource was retrieved.",
                        "schema": {"type": "string"},
                    },
                },
            },
        }
    },
)
async def forward_media_resource_request(
    request: Request,
    headers: Annotated[
        ForwardMediaResourceRequestHeaders,
        Depends(validated_forward_media_resource_request_headers),
    ],
    media_resource_gateway: Annotated[
        MediaResourceGateway, resolve_instance(MediaResourceGateway)
    ],
) -> Response:
    return await media_resource_gateway.get(request=request, headers=headers)
