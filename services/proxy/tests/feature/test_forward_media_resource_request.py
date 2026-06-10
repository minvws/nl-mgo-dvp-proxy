import logging

from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from inject import Binder
from pytest import LogCaptureFixture
from pytest_mock import MockerFixture

from app.forwarding.constants import MGO_MEDIA_RESOURCE_URL_HEADER
from app.main import create_app
from app.medmij.repositories import InMemoryWhitelistRepository, WhitelistRepository
from tests.utils import clear_bindings, configure_bindings

MEDIA_RESOURCE_HOSTNAME = "media.example.org"
MEDIA_RESOURCE_URL = f"https://{MEDIA_RESOURCE_HOSTNAME}/media/image.jpg"


def test_forward_media_resource_request_successfully_returns_upstream_response(
    mocker: MockerFixture,
) -> None:
    def bindings_override(binder: Binder) -> Binder:
        whitelist = InMemoryWhitelistRepository()
        whitelist.refresh_cache(
            [MEDIA_RESOURCE_HOSTNAME], synced_at="2024-01-01T00:00:00"
        )
        binder.bind(WhitelistRepository, whitelist)

        return binder

    configure_bindings(bindings_override=bindings_override)

    mock_upstream_call = mocker.patch(
        target="app.circuitbreaker.services.CircuitBreaker.call",
        new_callable=mocker.AsyncMock,
        return_value=HttpxResponse(
            status_code=200,
            content=b"image data",
            headers={"content-type": "image/jpeg"},
        ),
    )

    test_client = TestClient(create_app())

    response = test_client.get(
        "/gateway",
        headers={
            MGO_MEDIA_RESOURCE_URL_HEADER: MEDIA_RESOURCE_URL,
        },
    )

    assert response.status_code == 200
    assert response.content == b"image data"
    assert response.headers["content-type"] == "image/jpeg"

    mock_upstream_call.assert_awaited_once_with(
        identifier=MEDIA_RESOURCE_URL,
        func=mocker.ANY,
        url=MEDIA_RESOURCE_URL,
        headers=mocker.ANY,
    )

    clear_bindings()


def test_forward_media_resource_request_when_hostname_not_whitelisted_returns_error_response(
    caplog: LogCaptureFixture,
) -> None:
    def bindings_override(binder: Binder) -> Binder:
        binder.bind(WhitelistRepository, InMemoryWhitelistRepository())

        return binder

    configure_bindings(bindings_override=bindings_override)

    test_client = TestClient(create_app())

    logging.getLogger("app").addHandler(caplog.handler)

    response = test_client.get(
        "/gateway",
        headers={
            MGO_MEDIA_RESOURCE_URL_HEADER: MEDIA_RESOURCE_URL,
        },
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Request blocked due to whitelist error"}

    log_record = next(
        r
        for r in caplog.records
        if "Request blocked due to whitelist error" in r.message
    )
    assert log_record is not None
    log_record_exc = log_record.exc_info[1] if log_record.exc_info else None
    assert log_record_exc is not None
    assert (
        str(log_record_exc) == f"Hostname is not whitelisted: {MEDIA_RESOURCE_HOSTNAME}"
    )

    clear_bindings()
