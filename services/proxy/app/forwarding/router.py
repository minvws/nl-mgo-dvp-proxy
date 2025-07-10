from fastapi import APIRouter, Header, Request, Response
from pydantic import AnyHttpUrl

from app.forwarding.schemas import ProxyHeaders
from app.forwarding.services import ForwardingService
from app.utils import resolve_instance

from .constants import (
    DVA_TARGET_REQUEST_HEADER,
    FORWARD_URL_RESPONSE_HEADER,
    MEDMIJ_ACCESS_TOKEN_HEADER,
    TARGET_URL_SIGNATURE_QUERY_PARAM,
)

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
    dva_target_header: AnyHttpUrl = Header(
        ...,
        alias=DVA_TARGET_REQUEST_HEADER,
        description=(
            "The target URL of a specific data service to hit at a healthcare provider. "
            f"Include the ?{TARGET_URL_SIGNATURE_QUERY_PARAM}= parameter to verify the origin of the target URL."
        ),
        examples=[
            "https://mock",
            f"https://mock?{TARGET_URL_SIGNATURE_QUERY_PARAM}=base64_encoded_signature",
        ],
    ),
    oauth_access_token_header: str | None = Header(
        default=None,
        alias=MEDMIJ_ACCESS_TOKEN_HEADER,
        description=(
            "An access_token provided by a MedMij tokenserver. "
            f"Include the access token in the request headers using the {MEDMIJ_ACCESS_TOKEN_HEADER}."
        ),
        examples=[
            {
                "url": "https://dva-mock.test.mgo.prolocation.net/51",
                "headers": {
                    MEDMIJ_ACCESS_TOKEN_HEADER: "2f256b2f-fcef-4e47-97ff-b58894732dc9"
                },
            }
        ],
    ),
    correlation_id_header: str = Header(None, alias="X-Correlation-ID", min_length=1),
    forwarding_service: ForwardingService = resolve_instance(ForwardingService),
    x_mgo_provider_id: str | None = Header(None, alias="X-MGO-PROVIDER-ID"),
    x_mgo_service_id: int | None = Header(None, alias="X-MGO-SERVICE-ID"),
    accept: str = Header(None, alias="Accept"),
) -> Response:
    validated_headers = ProxyHeaders(
        dva_target=dva_target_header,
        oauth_access_token=oauth_access_token_header,
        correlation_id=correlation_id_header,
        x_mgo_provider_id=x_mgo_provider_id,
        x_mgo_service_id=x_mgo_service_id,
        accept=accept,
    )
    return await forwarding_service.get_resource(
        request=request, headers=validated_headers
    )
