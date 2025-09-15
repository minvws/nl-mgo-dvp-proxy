from fastapi import APIRouter, Request, Response, Depends
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY
from app.forwarding.schemas import ForwardingRequest
from app.forwarding.services import ForwardingService
from app.utils import resolve_instance

import inject

from pydantic import ValidationError

from app.forwarding.models import DvaTarget
from app.forwarding.schemas import ForwardingRequest
from app.forwarding.signing.exceptions import (
    DisallowedTargetHost,
    InvalidTargetUrlSignature,
    MissingTargetUrlSignature,
)
from app.forwarding.signing.services import DvaTargetVerifier
from fastapi import Header, HTTPException
from app.config.models import ForwardingConfig


from .constants import (
    FORWARD_URL_RESPONSE_HEADER,
    TARGET_URL_SIGNATURE_QUERY_PARAM,
)

from app.forwarding.constants import (
    DVA_TARGET_REQUEST_HEADER,
    MEDMIJ_ACCESS_TOKEN_HEADER,
    MEDMIJ_CORRELATION_ID_HEADER,
    MGO_DATASERVICE_ID_HEADER,
    MGO_HEALTHCARE_PROVIDER_ID_HEADER,
)

router = APIRouter()


@inject.autoparams("config")
def validate_healthcare_provider_id(
    healthcare_provider_id: str,
    config: ForwardingConfig,
) -> None:
    if config.require_provider_and_service_id and healthcare_provider_id is None:
        raise HTTPException(
            status_code=422,
            detail=f"Missing required header: {MGO_HEALTHCARE_PROVIDER_ID_HEADER}",
        )


@inject.autoparams("config")
def validate_dataservice_id(
    dataservice_id: int,
    config: ForwardingConfig,
) -> None:
    if config.require_provider_and_service_id and dataservice_id is None:
        raise HTTPException(
            status_code=422,
            detail=f"Missing required header: {MGO_DATASERVICE_ID_HEADER}",
        )


@inject.autoparams("dva_target_verifier")
async def validate_dva_target(
    dva_target: str,
    dva_target_verifier: DvaTargetVerifier,
) -> None:
    dva_target_model: DvaTarget = DvaTarget.from_dva_target_url(header=str(dva_target))
    try:
        await dva_target_verifier.verify(dva_target=dva_target_model)
    except (
        InvalidTargetUrlSignature,
        MissingTargetUrlSignature,
    ):
        raise HTTPException(403, "Invalid signature")
    except DisallowedTargetHost:
        raise HTTPException(403, "Forbidden")


async def validated_forwarding_request(
    dva_target: str = Header(
        ...,
        alias=DVA_TARGET_REQUEST_HEADER,
        description=(
            "The target URL of a specific data service to hit at a healthcare provider. "
            f"Include the ?{TARGET_URL_SIGNATURE_QUERY_PARAM}= parameter to verify the origin of the target URL."
        ),
        examples={  # type: ignore
            "signed": {
                "summary": "Signed",
                "value": "https://mock?target_url_signature=base64_encoded_signature",
            }
        },
    ),
    oauth_access_token: str = Header(
        None,
        alias=MEDMIJ_ACCESS_TOKEN_HEADER,
        description=(
            "An access_token provided by a MedMij tokenserver. "
            "Include the access token in the request headers using the MedMij-Access-Token."
        ),
        examples={  # type: ignore
            "default": {
                "summary": "Example",
                "value": "2f256b2f-fcef-4e47-97ff-b58894732dc9",
            }
        },
    ),
    correlation_id: str = Header(
        None,
        alias=MEDMIJ_CORRELATION_ID_HEADER,
        min_length=1,
        description="A unique identifier for correlating requests for tracing and debugging purposes.",
        examples={  # type: ignore
            "default": {
                "summary": "Example",
                "value": "123e4567-e89b-12d3-a456-426614174000",
            }
        },
    ),
    x_mgo_provider_id: str | None = Header(
        None,
        alias=MGO_HEALTHCARE_PROVIDER_ID_HEADER,
        description="The unique identifier of the healthcare provider to which the request is forwarded.",
        examples={  # type: ignore
            "default": {"summary": "Example", "value": "provider-12345"}
        },
    ),
    x_mgo_service_id: int | None = Header(
        None,
        alias=MGO_DATASERVICE_ID_HEADER,
        description="The unique identifier of the data service to which the request is forwarded.",
        examples={  # type: ignore
            "default": {"summary": "Example", "value": 42}
        },
    ),
    accept: str = Header(None, alias="Accept"),
) -> ForwardingRequest:
    try:
        forwarding_request = ForwardingRequest.model_validate(
            {
                DVA_TARGET_REQUEST_HEADER: dva_target,
                MEDMIJ_ACCESS_TOKEN_HEADER: oauth_access_token,
                MEDMIJ_CORRELATION_ID_HEADER: correlation_id,
                MGO_HEALTHCARE_PROVIDER_ID_HEADER: x_mgo_provider_id,
                MGO_DATASERVICE_ID_HEADER: x_mgo_service_id,
                "accept": accept,
            }
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=HTTP_422_UNPROCESSABLE_ENTITY,
            detail=e.errors(),
        )

    validate_healthcare_provider_id(
        healthcare_provider_id=forwarding_request.x_mgo_provider_id
    )
    validate_dataservice_id(dataservice_id=forwarding_request.x_mgo_service_id)
    await validate_dva_target(dva_target=forwarding_request.dva_target)

    return forwarding_request


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
    forwarding_request: ForwardingRequest = Depends(validated_forwarding_request),
    forwarding_service: ForwardingService = resolve_instance(ForwardingService),
) -> Response:
    return await forwarding_service.get_resource(
        request=request, headers=forwarding_request
    )
