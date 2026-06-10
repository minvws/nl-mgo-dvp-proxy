import logging
from typing import Any, cast

import faker
import pytest
from httpx import HTTPStatusError, Request, Response
from pytest_mock import MockerFixture, MockType

from app.medmij import services as medmij_services
from app.medmij.repositories import (
    FilesystemWhitelistXsdRepository,
    WhitelistRepository,
    XsdRepository,
)
from app.medmij.services import MedMijWhitelistPuller, WhitelistValidationError
from app.utils import root_path
from tests.utils import assert_captured_logs


@pytest.fixture
def whitelist_url() -> str:
    return faker.Faker().url()


@pytest.fixture
def whitelist_xsd_file_repo() -> XsdRepository:
    repo = FilesystemWhitelistXsdRepository()
    repo.add_schema_to_cache(
        MedMijWhitelistPuller.WHITELIST_XSD_LABEL,
        root_path("resources", "medmij", "MedMij_Whitelist.xsd"),
    )
    return repo


@pytest.fixture
def whitelist_repository(mocker: MockerFixture) -> MockType:
    repo: MockType = mocker.Mock(spec=WhitelistRepository)
    return repo


VALID_XML = """
<Whitelist xmlns="xmlns://afsprakenstelsel.medmij.nl/whitelist/release2/">
  <Tijdstempel>2021-04-16T10:43:41+01:00</Tijdstempel>
  <Volgnummer>28654</Volgnummer>
  <MedMijNodes>
    <MedMijNode>
      <Hostname>zanode.zorginstelling.nl</Hostname>
    </MedMijNode>
    <MedMijNode>
      <Hostname>mijn.zorginstelling.nl</Hostname>
    </MedMijNode>
  </MedMijNodes>
</Whitelist>
"""

INVALID_XML = """
<Invalid>
  <MedMijNodes>
    <MedMijNode>
      <Hostname>zanode.zorginstelling.nl</Hostname>
    </MedMijNode>
  </MedMijNodes>
</Invalid>
"""

VALID_XML_WITH_EMPTY_HOSTNAMES = """
<Whitelist xmlns="xmlns://afsprakenstelsel.medmij.nl/whitelist/release2/">
    <Tijdstempel>2021-04-16T10:43:41+01:00</Tijdstempel>
    <Volgnummer>28654</Volgnummer>
    <MedMijNodes />
</Whitelist>
"""


class StubResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class StubRetryingClient:
    def __init__(self, responses: list[StubResponse | Exception]) -> None:
        self.responses = responses
        self.calls = 0

    def get(self, url: str) -> StubResponse:
        _ = url
        response = self.responses[self.calls]
        self.calls += 1

        if isinstance(response, Exception):
            raise response

        return response


class TestMedMijWhitelistPuller:
    def test_pull_and_refresh_when_whitelist_is_valid_updates_cache(
        self,
        whitelist_url: str,
        whitelist_xsd_file_repo: XsdRepository,
        whitelist_repository: MockType,
    ) -> None:
        retrying_client = StubRetryingClient(
            [StubResponse(status_code=200, text=VALID_XML)]
        )

        service = MedMijWhitelistPuller(
            medmij_mtls_client=cast(Any, retrying_client),
            whitelist_repository=whitelist_repository,
            whitelist_url=whitelist_url,
            whitelist_xsd_file_repo=whitelist_xsd_file_repo,
        )

        count = service.pull_and_refresh()

        assert count == 2
        whitelist_repository.refresh_cache.assert_called_once()
        call_kwargs = whitelist_repository.refresh_cache.call_args.kwargs
        assert call_kwargs["hostnames"] == [
            "zanode.zorginstelling.nl",
            "mijn.zorginstelling.nl",
        ]
        assert isinstance(call_kwargs["synced_at"], str)
        assert call_kwargs["synced_at"] != ""

    def test_pull_and_refresh_when_validation_fails_keeps_current_cache(
        self,
        whitelist_url: str,
        whitelist_xsd_file_repo: XsdRepository,
        whitelist_repository: MockType,
    ) -> None:
        service = MedMijWhitelistPuller(
            medmij_mtls_client=cast(
                Any,
                StubRetryingClient([StubResponse(status_code=200, text=INVALID_XML)]),
            ),
            whitelist_repository=whitelist_repository,
            whitelist_url=whitelist_url,
            whitelist_xsd_file_repo=whitelist_xsd_file_repo,
        )

        with pytest.raises(WhitelistValidationError):
            service.pull_and_refresh()

        whitelist_repository.refresh_cache.assert_not_called()

    def test_pull_and_refresh_when_retries_are_exhausted_keeps_current_cache(
        self,
        whitelist_url: str,
        whitelist_xsd_file_repo: XsdRepository,
        whitelist_repository: MockType,
    ) -> None:
        service = MedMijWhitelistPuller(
            medmij_mtls_client=cast(
                Any,
                StubRetryingClient(
                    [
                        RuntimeError("retries exhausted"),
                    ]
                ),
            ),
            whitelist_repository=whitelist_repository,
            whitelist_url=whitelist_url,
            whitelist_xsd_file_repo=whitelist_xsd_file_repo,
        )

        with pytest.raises(RuntimeError):
            service.pull_and_refresh()

        whitelist_repository.refresh_cache.assert_not_called()

    def test_pull_and_refresh_when_http_status_error_occurs_logs_status_code(
        self,
        caplog: pytest.LogCaptureFixture,
        whitelist_url: str,
        whitelist_xsd_file_repo: XsdRepository,
        whitelist_repository: MockType,
    ) -> None:
        request = Request("GET", whitelist_url)
        response = Response(503, request=request)

        service = MedMijWhitelistPuller(
            medmij_mtls_client=cast(
                Any,
                StubRetryingClient(
                    [
                        HTTPStatusError(
                            "Server error",
                            request=request,
                            response=response,
                        ),
                    ]
                ),
            ),
            whitelist_repository=whitelist_repository,
            whitelist_url=whitelist_url,
            whitelist_xsd_file_repo=whitelist_xsd_file_repo,
        )

        medmij_services.logger.addHandler(caplog.handler)

        with pytest.raises(HTTPStatusError):
            service.pull_and_refresh()

        assert_captured_logs(
            caplog,
            [
                (
                    f"MedMij whitelist pull failed after retries exhausted: url={whitelist_url} status=503 error=Server error",
                    logging.ERROR,
                ),
            ],
        )
        assert any(
            record.message
            == f"MedMij whitelist pull failed after retries exhausted: url={whitelist_url} status=503 error=Server error"
            and record.exc_info is not None
            for record in caplog.records
        )

    def test_pull_and_refresh_when_whitelist_has_no_hostnames_raises_validation_error(
        self,
        whitelist_url: str,
        whitelist_xsd_file_repo: XsdRepository,
        whitelist_repository: MockType,
    ) -> None:
        service = MedMijWhitelistPuller(
            medmij_mtls_client=cast(
                Any,
                StubRetryingClient(
                    [StubResponse(status_code=200, text=VALID_XML_WITH_EMPTY_HOSTNAMES)]
                ),
            ),
            whitelist_repository=whitelist_repository,
            whitelist_url=whitelist_url,
            whitelist_xsd_file_repo=whitelist_xsd_file_repo,
        )

        with pytest.raises(
            WhitelistValidationError, match="did not contain any hostnames"
        ):
            service.pull_and_refresh()

        whitelist_repository.refresh_cache.assert_not_called()

    def test_pull_and_refresh_when_cache_refresh_fails_keeps_current_cache(
        self,
        caplog: pytest.LogCaptureFixture,
        whitelist_url: str,
        whitelist_xsd_file_repo: XsdRepository,
        whitelist_repository: MockType,
    ) -> None:
        whitelist_repository.refresh_cache.side_effect = RuntimeError(
            "redis unavailable"
        )

        service = MedMijWhitelistPuller(
            medmij_mtls_client=cast(
                Any, StubRetryingClient([StubResponse(200, VALID_XML)])
            ),
            whitelist_repository=whitelist_repository,
            whitelist_url=whitelist_url,
            whitelist_xsd_file_repo=whitelist_xsd_file_repo,
        )

        medmij_services.logger.addHandler(caplog.handler)

        with pytest.raises(RuntimeError, match="redis unavailable"):
            service.pull_and_refresh()

        assert_captured_logs(
            caplog,
            [
                (
                    "MedMij whitelist cache refresh failed: error=redis unavailable",
                    logging.ERROR,
                ),
            ],
        )
        assert any(
            record.message
            == "MedMij whitelist cache refresh failed: error=redis unavailable"
            and record.exc_info is not None
            for record in caplog.records
        )

    def test_pull_and_refresh_when_request_starts_logs_pull_message(
        self,
        caplog: pytest.LogCaptureFixture,
        whitelist_url: str,
        whitelist_xsd_file_repo: XsdRepository,
        whitelist_repository: MockType,
    ) -> None:
        caplog.set_level(logging.DEBUG, logger="app.medmij.services")

        service = MedMijWhitelistPuller(
            medmij_mtls_client=cast(
                Any, StubRetryingClient([StubResponse(200, VALID_XML)])
            ),
            whitelist_repository=whitelist_repository,
            whitelist_url=whitelist_url,
            whitelist_xsd_file_repo=whitelist_xsd_file_repo,
        )

        medmij_services.logger.addHandler(caplog.handler)
        service.pull_and_refresh()

        assert_captured_logs(
            caplog,
            [
                (
                    f"Pulling MedMij whitelist: url={whitelist_url}",
                    logging.DEBUG,
                ),
            ],
        )
