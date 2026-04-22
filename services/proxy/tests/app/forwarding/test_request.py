from typing import Literal

import pytest
from faker import Faker
from fastapi.testclient import TestClient
from inject import Binder
from pydantic import AnyHttpUrl, ValidationError
from pytest_mock import MockerFixture

from app.config.models import ForwardingConfig
from app.forwarding.constants import (
    DVA_TARGET_REQUEST_HEADER,
    MGO_DATASERVICE_ID_HEADER,
    MGO_HEALTHCARE_PROVIDER_ID_HEADER,
)
from app.forwarding.schemas import ForwardingRequest
from app.security.dva_target.services import DvaTargetAssertionParser
from tests.utils import configure_bindings


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "provider_id,service_id,missing",
    [
        (None, None, MGO_HEALTHCARE_PROVIDER_ID_HEADER),
        ("provider", None, MGO_DATASERVICE_ID_HEADER),
        (None, 42, MGO_HEALTHCARE_PROVIDER_ID_HEADER),
    ],
)
async def test_validate_missing_headers_when_requires_provider_and_service_id_raises_exception(
    test_client: TestClient,
    mocker: MockerFixture,
    faker: Faker,
    mock_dva_endpoint_jwe: str,
    provider_id: None | Literal["provider"],
    service_id: None | Literal[42],
    missing: str,
) -> None:
    mock_dva_target_assertion_parser = mocker.Mock(spec=DvaTargetAssertionParser)
    config: ForwardingConfig = mocker.Mock(ForwardingConfig)
    config.require_provider_and_service_id = True

    mock_dva_target_assertion_parser.parse.return_value = AnyHttpUrl(faker.url())

    def bindings_override(binder: Binder) -> Binder:
        binder.bind(DvaTargetAssertionParser, mock_dva_target_assertion_parser)
        binder.bind(ForwardingConfig, config)
        return binder

    configure_bindings(
        bindings_override=bindings_override,
    )

    header_dict = {
        "accept": "application/fhir+json",
        DVA_TARGET_REQUEST_HEADER: mock_dva_endpoint_jwe,
    }
    if provider_id is not None:
        header_dict[MGO_HEALTHCARE_PROVIDER_ID_HEADER] = provider_id
    if service_id is not None:
        header_dict[MGO_DATASERVICE_ID_HEADER] = str(service_id)

    response = test_client.get(
        "/fhir/patient?foo=bar",
        headers=header_dict,
    )

    assert response.status_code == 422
    assert missing in response.json()["detail"]


def test_forwarding_request_with_invalid_service_id_raises_an_error(
    mock_dva_endpoint_jwe: str,
) -> None:
    with pytest.raises(ValidationError) as exc_info:
        ForwardingRequest(
            dva_target=mock_dva_endpoint_jwe,
            x_mgo_service_id="not-an-integer",
            accept="application/fhir+json",
        )  # type: ignore[call-arg]
    errors = exc_info.value.errors()
    assert any(
        e["loc"] == ("x_mgo_service_id",) and e["type"].startswith("int_parsing")
        for e in errors
    )
