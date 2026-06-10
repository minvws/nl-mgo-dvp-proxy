from dataclasses import dataclass
from typing import Annotated

from fastapi import Header

from .constants import (
    MEDMIJ_ACCESS_TOKEN_HEADER,
    MEDMIJ_CORRELATION_ID_HEADER,
    MGO_DATASERVICE_ID_HEADER,
    MGO_HEALTHCARE_PROVIDER_ID_HEADER,
)

MedMijCorrelationIdHeader = Annotated[
    str | None,
    Header(
        alias=MEDMIJ_CORRELATION_ID_HEADER,
        min_length=1,
        description="A unique identifier for correlating requests for tracing and debugging purposes.",
        examples={
            "default": {
                "summary": "Example",
                "value": "123e4567-e89b-12d3-a456-426614174000",
            }
        },
    ),
]

MedMijOAuthAccessTokenHeader = Annotated[
    str | None,
    Header(
        alias=MEDMIJ_ACCESS_TOKEN_HEADER,
        description=(
            "An access_token provided by a MedMij tokenserver. "
            "Include the access token in the request headers using the MedMij-Access-Token."
        ),
        examples={
            "default": {
                "summary": "Example",
                "value": "2f256b2f-fcef-4e47-97ff-b58894732dc9",
            }
        },
    ),
]

MGOHealthCareProviderIDHeader = Annotated[
    str | None,
    Header(
        alias=MGO_HEALTHCARE_PROVIDER_ID_HEADER,
        description="The unique identifier of the healthcare provider to which the request is forwarded.",
        examples={"default": {"summary": "Example", "value": "provider-12345"}},
    ),
]

MGODataServiceIDHeader = Annotated[
    int | None,
    Header(
        alias=MGO_DATASERVICE_ID_HEADER,
        description="The unique identifier of the data service to which the request is forwarded.",
        examples={"default": {"summary": "Example", "value": 42}},
    ),
]

MGOAcceptHeader = Annotated[
    str | None,
    Header(
        alias="Accept",
        description=(
            "Accept header that is used to specify the FHIR version"
            "(for example: application/fhir+json; fhirVersion=3.0)."
        ),
    ),
]


@dataclass(frozen=True)
class ForwardingRequestHeaders:
    dva_target_url: str
    oauth_access_token: str | None
    correlation_id: str | None
    x_mgo_provider_id: str | None
    x_mgo_service_id: int | None
    accept: str | None


@dataclass(frozen=True)
class RetryErrorContext:
    status_code: int | None
    error_message: str | None


@dataclass(frozen=True)
class ForwardMediaResourceRequestHeaders:
    media_resource_url: str
    access_token: str | None
    correlation_id: str | None
    healthcare_provider_id: str | None
    data_service_id: int | None
