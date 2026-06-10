import logging
from datetime import datetime
from time import monotonic
from typing import Final, List
from xml.etree import ElementTree

import inject
from httpx import HTTPStatusError, Response

from app.http_client.clients import SyncPkioMTLSClient
from app.medmij.repositories import WhitelistRepository, XsdRepository

logger = logging.getLogger(__name__)


class WhitelistValidationError(Exception):
    pass


class MedMijWhitelistPuller:
    HOSTNAME_XPATH: Final[str] = ".//{*}Hostname"
    WHITELIST_XSD_LABEL: Final[str] = "medmij-whl"

    @inject.autoparams(
        "medmij_mtls_client",
        "whitelist_repository",
        "whitelist_url",
        "whitelist_xsd_file_repo",
    )
    def __init__(
        self,
        medmij_mtls_client: SyncPkioMTLSClient,
        whitelist_repository: WhitelistRepository,
        whitelist_url: str,
        whitelist_xsd_file_repo: XsdRepository,
    ) -> None:
        self.__client = medmij_mtls_client
        self.__whitelist_repository = whitelist_repository
        self.__whitelist_url = whitelist_url
        self.__xsd_schema = whitelist_xsd_file_repo.get_schema_from_cache(
            self.WHITELIST_XSD_LABEL
        )

    def pull_and_refresh(self) -> int:
        start = monotonic()

        response = self._fetch_whitelist_xml()
        try:
            hostnames = self._extract_hostnames(response.text)
        except WhitelistValidationError as exception:
            self.__log_xml_validation_error(exception)
            raise

        synced_at = datetime.now().isoformat()
        try:
            self.__whitelist_repository.refresh_cache(
                hostnames=hostnames, synced_at=synced_at
            )
        except Exception as exception:
            self.__log_cache_refresh_error(exception)
            raise

        duration_ms = int((monotonic() - start) * 1000)

        logger.info(
            "MedMij whitelist pull successful: url=%s status=%s hostnames=%s duration_ms=%s",
            self.__whitelist_url,
            response.status_code,
            len(hostnames),
            duration_ms,
        )

        return len(hostnames)

    def _fetch_whitelist_xml(self) -> Response:
        logger.debug(
            "Pulling MedMij whitelist: url=%s",
            self.__whitelist_url,
        )

        try:
            response = self.__client.get(self.__whitelist_url)
            response.raise_for_status()
        except Exception as exception:
            self.__log_whitelist_pull_error(exception)
            raise

        return response

    def _extract_hostnames(self, xml_data: str) -> List[str]:
        try:
            self.__xsd_schema.validate(xml_data)
            root = ElementTree.fromstring(xml_data)
        except Exception as exception:
            raise WhitelistValidationError(str(exception)) from exception

        hostnames = [
            node.text.strip()
            for node in root.findall(self.HOSTNAME_XPATH)
            if node.text is not None and node.text.strip() != ""
        ]

        if len(hostnames) == 0:
            raise WhitelistValidationError("Whitelist did not contain any hostnames")

        return hostnames

    def __get_error_status(self, exception: Exception) -> int | str:
        if isinstance(exception, HTTPStatusError):
            return exception.response.status_code

        return "request-failed"

    def __log_xml_validation_error(self, exception: WhitelistValidationError) -> None:
        logger.error(
            "MedMij whitelist XML validation failed: error=%s",
            str(exception),
            exc_info=exception,
        )

    def __log_cache_refresh_error(self, exception: Exception) -> None:
        logger.error(
            "MedMij whitelist cache refresh failed: error=%s",
            str(exception),
            exc_info=exception,
        )

    def __log_whitelist_pull_error(self, exception: Exception) -> None:
        logger.error(
            "MedMij whitelist pull failed after retries exhausted: url=%s status=%s error=%s",
            self.__whitelist_url,
            self.__get_error_status(exception),
            str(exception),
            exc_info=exception,
        )
