from typing import Literal
from fastapi import HTTPException
from fastapi.testclient import TestClient

from pydantic import ValidationError

import pytest
from pytest_mock import MockerFixture


from app.forwarding.router import validate_dva_target
from app.forwarding.models import DvaTarget
from app.forwarding.signing.exceptions import (
    DisallowedTargetHost,
    InvalidTargetUrlSignature,
    MissingTargetUrlSignature,
)
from app.forwarding.signing.services import DvaTargetVerifier

from app.forwarding.constants import (
    DVA_TARGET_REQUEST_HEADER,
    MGO_HEALTHCARE_PROVIDER_ID_HEADER,
    MGO_DATASERVICE_ID_HEADER,
)
from app.config.models import ForwardingConfig
from app.forwarding.schemas import ForwardingRequest
from tests.utils import configure_bindings


@pytest.mark.asyncio
async def test_get_and_verify_dva_target_disallowed_host(mocker: MockerFixture) -> None:
    mock_verifier = mocker.Mock(DvaTargetVerifier)
    mock_dva_target: DvaTarget = DvaTarget.from_dva_target_url(
        "https://example.com/resource"
    )

    mocker.patch.object(
        mock_verifier,
        "verify",
        side_effect=mocker.Mock(side_effect=DisallowedTargetHost("example.com")),
    )
    with pytest.raises(HTTPException) as exc_info:
        await validate_dva_target(str(mock_dva_target), mock_verifier)

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Forbidden"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception",
    [InvalidTargetUrlSignature(errors=["Some error"]), MissingTargetUrlSignature()],
)
async def test_get_and_verify_dva_target_invalid_signature(
    mocker: MockerFixture, exception: Exception
) -> None:
    mock_verifier = mocker.Mock(DvaTargetVerifier)
    mock_dva_target: DvaTarget = DvaTarget.from_dva_target_url(
        "https://example.com/resource"
    )

    mocker.patch.object(DvaTarget, "from_dva_target_url", return_value=mock_dva_target)
    mock_verifier.verify.side_effect = exception

    with pytest.raises(HTTPException) as exc_info:
        await validate_dva_target(str(mock_dva_target), mock_verifier)

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Invalid signature"


@pytest.mark.asyncio
async def test_verify_dva_target_success(mocker: MockerFixture) -> None:
    mock_verifier: DvaTargetVerifier = mocker.Mock(DvaTargetVerifier)
    mock_dva_target: DvaTarget = DvaTarget.from_dva_target_url(
        header=str("https://example.com/fhir/patient")
    )

    mocker.patch.object(DvaTarget, "from_dva_target_url", return_value=mock_dva_target)
    mock_verifier_verify = mocker.patch.object(
        mock_verifier, "verify", mocker.AsyncMock(return_value=None)
    )

    await validate_dva_target(str(mock_dva_target), mock_verifier)
    mock_verifier_verify.assert_awaited_once_with(dva_target=mock_dva_target)


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
    provider_id: None | Literal["provider"],
    service_id: None | Literal[42],
    missing: str,
) -> None:
    config: ForwardingConfig = mocker.Mock(ForwardingConfig)
    config.require_provider_and_service_id = True

    configure_bindings(
        bindings_override=lambda binder: binder.bind(ForwardingConfig, config),
    )

    header_dict = {
        "accept": "application/fhir+json",
        "X-MGO-DVA-TARGET": "https://example.com/resource",
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


def test_forwarding_request_invalid_dva_target_returns_422(
    test_client: TestClient,
) -> None:
    # Provide an invalid URL for dva_target to trigger a ValidationError
    headers = {"X-MGO-DVA-TARGET": "not-a-valid-url"}
    response = test_client.get("/fhir/patient?foo=bar", headers=headers)
    assert response.status_code == 422
    # The response should include details about the validation error
    data = response.json()
    assert "detail" in data
    # Optionally, check that the error is about dva_target
    assert any(
        err.get("loc", [None])[-1] == DVA_TARGET_REQUEST_HEADER
        for err in data["detail"]
    )


def test_forwarding_request_with_invalid_dva_target_raises_an_error() -> None:
    with pytest.raises(ValidationError) as exc_info:
        ForwardingRequest(
            dva_target="not-a-valid-url",
            oauth_access_token="token",
            correlation_id="corr-id",
            x_mgo_provider_id="provider-123",
            x_mgo_service_id=42,
            accept="application/fhir+json",
        )  # type: ignore[call-arg]
    errors = exc_info.value.errors()
    assert any(
        e["loc"] == ("dva_target",) and e["type"].startswith("url") for e in errors
    )


def test_forwarding_request_with_invalid_service_id_raises_an_error() -> None:
    with pytest.raises(ValidationError) as exc_info:
        ForwardingRequest(
            dva_target="https://example.com/resource",
            x_mgo_service_id="not-an-integer",
            accept="application/fhir+json",
        )  # type: ignore[call-arg]
    errors = exc_info.value.errors()
    assert any(
        e["loc"] == ("x_mgo_service_id",) and e["type"].startswith("int_parsing")
        for e in errors
    )


def test_forwarding_request_with_missing_dva_target_raises_an_error() -> None:
    with pytest.raises(ValidationError) as exc_info:
        ForwardingRequest(
            accept="application/fhir+json",
        )  # type: ignore[call-arg]
    errors = exc_info.value.errors()
    assert any(
        e["loc"] == (DVA_TARGET_REQUEST_HEADER,) and e["type"].startswith("missing")
        for e in errors
    )
