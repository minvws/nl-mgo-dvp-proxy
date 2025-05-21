import uuid
from logging import Logger
from typing import Any, Optional

import inject
from fastapi import HTTPException, Request, Response
from httpx import AsyncClient, TimeoutException
from httpx import Response as HttpxResponse
from opentelemetry.propagate import inject as op_inject

from app.circuitbreaker.models import CircuitOpenException
from app.circuitbreaker.services import CircuitBreakerService
from app.forwarding.constants import FORWARD_URL_RESPONSE_HEADER
from app.forwarding.models import DvaTarget
from app.forwarding.schemas import ProxyHeaders
from app.medmij_logging.constants import WWW_AUTHENTICATE_HEADER
from app.medmij_logging.factories import LogMessageFactory
from app.medmij_logging.services import (
    MedMijLogger,
    ServerIdentifier,
    WWWAuthenticateParser,
)

from .schemas import ProxyHeaders
from .signing.exceptions import (
    DisallowedTargetHost,
    InvalidTargetUrlSignature,
    MissingTargetUrlSignature,
)
from .signing.services import DvaTargetVerifier


class RequestForwardingLogHandler:
    @inject.autoparams()
    def __init__(
        self,
        medmij_logger: MedMijLogger,
        log_message_factory: LogMessageFactory,
        www_authenticate_parser: WWWAuthenticateParser,
    ) -> None:
        self._medmij_logger: MedMijLogger = medmij_logger
        self._log_message_factory: LogMessageFactory = log_message_factory
        self._www_authenticate_parser: WWWAuthenticateParser = www_authenticate_parser

    def handle_send_resource_request_log(
        self,
        session_id: str,
        trace_id: str,
        request_id: str,
        forward_url: str,
        request_method: str,
        service_id: int | None,
        provider_id: str | None,
    ) -> None:
        resource_request_log_message = (
            self._log_message_factory.create_send_resource_request_message(
                session_id=session_id,
                trace_id=trace_id,
                request_id=request_id,
                server_id=ServerIdentifier.get_server_id_for_uri(forward_url),
                method=request_method,
                resource_server_uri=forward_url,
                provider_id=provider_id,
                service_id=service_id,
            )
        )

        self._medmij_logger.log(resource_request_log_message)

    def handle_resource_response_log(
        self,
        request_id: str,
        session_id: str,
        trace_id: str,
        response_status_code: int,
        www_authenticate_header: Optional[str] = None,
    ) -> None:
        # Check for predefined request error scenarios that provide more context via the WWW-Authenticate header
        if response_status_code in [400, 401, 403]:
            error_context_params = {}

            if www_authenticate_header:
                error_context = self._www_authenticate_parser.parse(
                    www_authenticate_header
                )
                if error_context.error:
                    error_context_params["error_code"] = error_context.error
                if error_context.error_description:
                    error_context_params["error_description"] = (
                        error_context.error_description
                    )

            self.__log_receive_resource_request_error(
                request_id=request_id,
                session_id=session_id,
                trace_id=trace_id,
                response_status_code=response_status_code,
                **error_context_params,
            )

            return

        # Check for other resource error responses without context
        if response_status_code > 400:
            error_context_params = (
                {
                    "error_code": "temporarily_unavailable",
                    "error_description": "request timed out",
                }
                if response_status_code == 408
                else {}
            )

            self.__log_receive_resource_error_response(
                request_id=request_id,
                session_id=session_id,
                trace_id=trace_id,
                response_status_code=response_status_code,
                **error_context_params,
            )

            return

        self.__log_receive_resource_success_response(
            request_id=request_id,
            session_id=session_id,
            trace_id=trace_id,
            status_code=response_status_code,
        )

    def __log_receive_resource_success_response(
        self,
        request_id: str,
        session_id: str,
        trace_id: str,
        status_code: int,
    ) -> None:
        response_log_message = (
            self._log_message_factory.create_receive_resource_response(
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
                status_code=status_code,
            )
        )

        self._medmij_logger.log(response_log_message)

    def __log_receive_resource_request_error(
        self,
        request_id: str,
        session_id: str,
        trace_id: str,
        response_status_code: int,
        error_code: str = "other",
        error_description: str = "",
    ) -> None:
        response_log_message = (
            self._log_message_factory.create_receive_resource_request_error(
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
                status_code=response_status_code,
                description=error_description,
                error_code=error_code,
            )
        )

        self._medmij_logger.log(response_log_message)

    def __log_receive_resource_error_response(
        self,
        request_id: str,
        session_id: str,
        trace_id: str,
        response_status_code: int,
        error_code: str = "other",
        error_description: str = "",
    ) -> None:
        response_log_message = (
            self._log_message_factory.create_receive_resource_error_response(
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
                status_code=response_status_code,
                description=error_description,
                error_code=error_code,
            )
        )

        self._medmij_logger.log(response_log_message)


class ForwardingService:
    @inject.autoparams()
    def __init__(
        self,
        circuit_breaker: CircuitBreakerService,
        async_client: AsyncClient,
        logger: Logger,
        request_forwarding_log_handler: RequestForwardingLogHandler,
    ) -> None:
        self.circuit_breaker: CircuitBreakerService = circuit_breaker
        self.async_client: AsyncClient = async_client
        self.logger: Logger = logger
        self._request_forwarding_log_handler: RequestForwardingLogHandler = (
            request_forwarding_log_handler
        )

    @inject.autoparams()
    async def verify_dva_target(
        self,
        headers: ProxyHeaders,
        dva_target_verifier: DvaTargetVerifier,
    ) -> None:
        dva_target: DvaTarget = DvaTarget.from_dva_target_url(
            header=str(headers.dva_target)
        )

        try:
            await dva_target_verifier.verify(dva_target=dva_target)
        except (
            InvalidTargetUrlSignature,
            MissingTargetUrlSignature,
        ):
            raise HTTPException(403, "Invalid signature")
        except DisallowedTargetHost:
            raise HTTPException(403, "Forbidden")

    def get_forward_headers(self, headers: ProxyHeaders) -> dict[str, str]:
        forward_headers: dict[str, str] = {
            "MedMij-Request-ID": str(uuid.uuid4()),
            "Accept": headers.accept,
        }

        if headers.correlation_id:
            forward_headers["X-Correlation-ID"] = headers.correlation_id

        if headers.oauth_access_token:
            forward_headers["Authorization"] = f"Bearer {headers.oauth_access_token}"

        return forward_headers

    def generate_forward_url(
        self, target_url: str, path: str, query: str | None
    ) -> str:
        """
        Generates a full URL for forwarding a request by combining the target URL, path, and query string.

        Args:
            target_url (str): The base URL to which the request will be forwarded.
            path (str): The path to be appended to the target URL. Must start with a "/".
            query (str | None): The query string to be appended to the URL, if any. Should not start with a "?".

        Returns:
            str: The full URL constructed by combining the target URL, path, and query string.
        """
        if not path.startswith("/"):
            raise ValueError("The path must start with a '/'.")

        if query and query.startswith("?"):
            raise ValueError("The query string must not start with a '?'.")

        query_string = f"?{query}" if query else ""
        return f"{target_url.rstrip('/')}{path}{query_string}"

    def filter_response_headers(self, headers: dict[Any, Any]) -> dict[Any, Any]:
        excluded_headers: set[str] = {
            "transfer-encoding",
            "connection",
            "vary",
            "x-powered-by",
            "content-encoding",
            "content-length",
            "strict-transport-security",
            "referrer",
            "set-cookie",
            "server",
        }

        return {
            key: value
            for key, value in headers.items()
            if key.lower() not in excluded_headers
        }

    async def get_resource(self, request: Request, headers: ProxyHeaders) -> Response:
        await self.verify_dva_target(headers=headers)

        dva_target: DvaTarget = DvaTarget.from_dva_target_url(str(headers.dva_target))

        # Get target_url which is already stripped of the signature
        target_url: str = dva_target.target_url
        path: str = request.url.path
        query: str = request.url.query

        forward_url: str = self.generate_forward_url(
            target_url=target_url, path=path, query=query
        )
        forward_headers: dict[str, str] = self.get_forward_headers(headers=headers)
        op_inject(forward_headers)
        trace_id = str(
            headers.correlation_id if headers.correlation_id else uuid.uuid4()
        )

        self._request_forwarding_log_handler.handle_send_resource_request_log(
            session_id=uuid.uuid4().hex,
            request_id=forward_headers["MedMij-Request-ID"],
            trace_id=trace_id,
            forward_url=forward_url,
            request_method=request.method,
            provider_id=headers.x_mgo_provider_id,
            service_id=headers.x_mgo_service_id,
        )

        try:
            httpx_response: HttpxResponse = await self.circuit_breaker.call(
                identifier=forward_url,
                func=self.async_client.get,
                url=forward_url,
                headers=forward_headers,
            )
        except (TimeoutException, CircuitOpenException) as exc:
            self.logger.error(
                f"TimeoutException occurred while forwarding request to {forward_url}",
                exc_info=exc,
            )

            self._request_forwarding_log_handler.handle_resource_response_log(
                forward_headers["MedMij-Request-ID"],
                trace_id=trace_id,
                session_id=uuid.uuid4().hex,  # session id is generated as the DVP Proxy does not keep sessions
                response_status_code=408,
            )

            # METRIC: A metric should be emitted here to track the number of timeouts
            raise (
                HTTPException(504, "Gateway timeout")
                if type(exc) == TimeoutException
                else HTTPException(status_code=502, detail="Bad gateway")
            )

        self._request_forwarding_log_handler.handle_resource_response_log(
            httpx_response.headers.get("MedMij-Request-ID", ""),
            trace_id=trace_id,
            session_id=uuid.uuid4().hex,  # session id is generated as the DVP Proxy does not keep sessions
            response_status_code=httpx_response.status_code,
            www_authenticate_header=httpx_response.headers.get(WWW_AUTHENTICATE_HEADER),
        )

        self.logger.info(
            f"Executed Forward request to {forward_url} and received status code {httpx_response.status_code}"
        )

        response_headers: dict[Any, Any] = self.filter_response_headers(
            headers=dict(httpx_response.headers)
        )

        response_headers[FORWARD_URL_RESPONSE_HEADER] = str(forward_url)

        return Response(
            content=httpx_response.content,
            status_code=httpx_response.status_code,
            headers=response_headers,
        )
