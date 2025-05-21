import re
from dataclasses import dataclass
from logging import Logger
from typing import Optional
from urllib import parse

from .schemas import LogMessage


class ServerIdentifier:
    """Extracts the server id from a given URI"""

    @staticmethod
    def get_server_id_for_uri(uri: str) -> str:
        parsed_uri = parse.urlparse(uri)
        fqdn = parsed_uri.hostname

        if fqdn is None:
            raise ValueError("Invalid token server URI: missing hostname")

        return fqdn


class MedMijLogger:
    def __init__(self, logger: Logger) -> None:
        self.__logger = logger

    def log(self, log_message: LogMessage) -> None:
        self.__logger.info("medmij", extra={"log_message": log_message.model_dump()})


@dataclass
class WWWAuthenticateErrorContext:
    """
    A data class representing error context extracted from the
    WWW-Authenticate header.
    """

    error: Optional[str]
    error_description: Optional[str]


class WWWAuthenticateParser:
    """
    A parser for the WWW-Authenticate header from an HTTP response.
    This class extracts the 'error' and 'error_description' attributes
    from the header following RFC 6750. It does this by using a regex.
    """

    def parse(self, www_authenticate_header: str) -> WWWAuthenticateErrorContext:
        return WWWAuthenticateErrorContext(
            error=self.__extract_parameter(www_authenticate_header, "error"),
            error_description=self.__extract_parameter(
                www_authenticate_header, "error_description"
            ),
        )

    def __extract_parameter(self, header: str, parameter: str) -> Optional[str]:
        """
        The regex pattern used is: rf'{parameter}="([^"]+)"'
            - {parameter}: Matches the parameter name followed by an equals sign and a double quote.
            - ([^"]+): Captures one or more characters that are not double quotes.
        """
        pattern = re.compile(rf'{parameter}="([^"]+)"', re.IGNORECASE)
        match = pattern.search(header)

        return match.group(1) if match else None
