from abc import ABC, abstractmethod
from typing import Any
from uuid import uuid4

from opentelemetry import propagate

from app.forwarding.constants import (
    MEDMIJ_CORRELATION_ID_HEADER,
    MEDMIJ_REQUEST_ID_HEADER,
)
from app.forwarding.schemas import ForwardMediaResourceRequestHeaders


class MediaResourceGatewayHeaderFactory(ABC):
    @abstractmethod
    def create(
        self, request_headers: ForwardMediaResourceRequestHeaders
    ) -> dict[str, Any]: ...


class MinimalMediaResourceGatewayHeaderFactory(MediaResourceGatewayHeaderFactory):
    def create(
        self, request_headers: ForwardMediaResourceRequestHeaders
    ) -> dict[str, Any]:
        headers = {
            MEDMIJ_REQUEST_ID_HEADER: str(uuid4()),
        }

        if request_headers.correlation_id is not None:
            headers[MEDMIJ_CORRELATION_ID_HEADER] = request_headers.correlation_id

        if request_headers.access_token is not None:
            headers["Authorization"] = f"Bearer {request_headers.access_token}"

        return headers


class OpenTelemetryMediaResourceGatewayHeaderFactory(MediaResourceGatewayHeaderFactory):
    def __init__(self, decorated: MediaResourceGatewayHeaderFactory) -> None:
        self.__decorated = decorated

    def create(
        self, request_headers: ForwardMediaResourceRequestHeaders
    ) -> dict[str, Any]:
        headers = self.__decorated.create(request_headers)

        propagate.inject(headers)

        return headers
