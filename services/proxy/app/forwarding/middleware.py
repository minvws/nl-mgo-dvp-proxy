import logging
from typing import Annotated
from urllib.parse import urlparse

from fastapi import Depends, Header, HTTPException

from app.config.models import ForwardingConfig
from app.medmij.repositories import WhitelistRepository
from app.security.dva_target.services import DvaTargetAssertionParser
from app.utils import resolve_instance

from .constants import (
    DVA_TARGET_REQUEST_HEADER,
    MGO_DATASERVICE_ID_HEADER,
    MGO_HEALTHCARE_PROVIDER_ID_HEADER,
    MGO_MEDIA_RESOURCE_URL_HEADER,
)
from .schemas import (
    ForwardingRequestHeaders,
    ForwardMediaResourceRequestHeaders,
    MedMijCorrelationIdHeader,
    MedMijOAuthAccessTokenHeader,
    MGOAcceptHeader,
    MGODataServiceIDHeader,
    MGOHealthCareProviderIDHeader,
)

logger = logging.getLogger(__name__)


def validated_healthcare_provider_id_header(
    config: Annotated[ForwardingConfig, resolve_instance(ForwardingConfig)],
    x_mgo_provider_id: MGOHealthCareProviderIDHeader = None,
) -> str | None:
    if config.require_provider_and_service_id and x_mgo_provider_id is None:
        raise HTTPException(
            status_code=422,
            detail=f"Missing required header: {MGO_HEALTHCARE_PROVIDER_ID_HEADER}",
        )

    return x_mgo_provider_id


def validated_data_service_id_header(
    config: Annotated[ForwardingConfig, resolve_instance(ForwardingConfig)],
    x_mgo_service_id: MGODataServiceIDHeader = None,
) -> int | None:
    if config.require_provider_and_service_id and x_mgo_service_id is None:
        raise HTTPException(
            status_code=422,
            detail=f"Missing required header: {MGO_DATASERVICE_ID_HEADER}",
        )

    return x_mgo_service_id


def parsed_dva_target_url(
    dva_target_assertion_parser: DvaTargetAssertionParser = resolve_instance(
        DvaTargetAssertionParser
    ),
    dva_target_jwe: str = Header(
        alias=DVA_TARGET_REQUEST_HEADER,
        description="A JWE containing a signed JWT which includes the target URL as claim.",
    ),
) -> str:
    return dva_target_assertion_parser.parse(
        serialized_jwe=dva_target_jwe,
        error_context={"field": DVA_TARGET_REQUEST_HEADER},
    )


def validated_media_resource_url(
    media_resource_url: Annotated[
        str,
        Header(
            alias=MGO_MEDIA_RESOURCE_URL_HEADER,
            min_length=1,
            description="The URL of the media resource to retrieve.",
            examples={
                "default": {
                    "summary": "Example",
                    "value": "https://example.org/media/image12345.jpg",
                }
            },
        ),
    ],
    whitelist_repository: Annotated[
        WhitelistRepository, resolve_instance(WhitelistRepository)
    ],
) -> str:
    try:
        media_resource_hostname = urlparse(media_resource_url).hostname or ""
    except Exception:
        logger.exception(f"Invalid media resource URL: {media_resource_url}")

        media_resource_hostname = ""

    whitelist_repository.assert_whitelisted(media_resource_hostname)

    return media_resource_url


def validated_forwarding_request_headers(
    dva_target_url: Annotated[str, Depends(parsed_dva_target_url)],
    x_mgo_provider_id: Annotated[
        str | None, Depends(validated_healthcare_provider_id_header)
    ],
    x_mgo_service_id: Annotated[int | None, Depends(validated_data_service_id_header)],
    oauth_access_token: MedMijOAuthAccessTokenHeader = None,
    correlation_id: MedMijCorrelationIdHeader = None,
    accept: MGOAcceptHeader = None,
) -> ForwardingRequestHeaders:
    return ForwardingRequestHeaders(
        dva_target_url=dva_target_url,
        oauth_access_token=oauth_access_token,
        correlation_id=correlation_id,
        x_mgo_provider_id=x_mgo_provider_id,
        x_mgo_service_id=x_mgo_service_id,
        accept=accept,
    )


def validated_forward_media_resource_request_headers(
    media_resource_url: Annotated[str, Depends(validated_media_resource_url)],
    healthcare_provider_id: Annotated[
        str | None, Depends(validated_healthcare_provider_id_header)
    ],
    data_service_id: Annotated[int | None, Depends(validated_data_service_id_header)],
    correlation_id: MedMijCorrelationIdHeader = None,
    access_token: MedMijOAuthAccessTokenHeader = None,
) -> ForwardMediaResourceRequestHeaders:
    return ForwardMediaResourceRequestHeaders(
        media_resource_url=media_resource_url,
        access_token=access_token,
        healthcare_provider_id=healthcare_provider_id,
        data_service_id=data_service_id,
        correlation_id=correlation_id,
    )
