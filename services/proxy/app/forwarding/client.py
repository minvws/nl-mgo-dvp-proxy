import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from time import perf_counter
from time import sleep as blocking_sleep
from typing import Any, Callable, Final

import inject
from anyio import sleep as async_sleep
from httpx import AsyncClient, Client, Response, TransportError

from app.forwarding.schemas import RetryErrorContext
from app.metrics.service import MetricService

logger = logging.getLogger(__name__)


class RetryingHttpClientBase:
    """
    Shared implementation for HTTP clients with retry logic.
    Async and sync wrappers only provide the transport (HTTP call and sleep).
    """

    DEFAULT_MAX_RETRY_AFTER_SECS: Final[float] = 60.0
    RETRYABLE_STATUS_CODES: Final[set[int]] = {429, 500, 502, 503, 504}

    def __init__(
        self,
        metric_service: MetricService,
        max_retries: int = 3,
        backoff: float = 3,
        backoff_factor: float = 2,
        max_retry_after_secs: float = DEFAULT_MAX_RETRY_AFTER_SECS,
    ) -> None:
        self._validate_retry_config(
            max_retries=max_retries,
            backoff=backoff,
            backoff_factor=backoff_factor,
            max_retry_after_secs=max_retry_after_secs,
        )
        self.__max_retries = max_retries
        self.__backoff = backoff
        self.__backoff_factor = backoff_factor
        self.__max_retry_after_secs = max_retry_after_secs
        self.__metric_service = metric_service

    def _validate_retry_config(
        self,
        *,
        max_retries: int,
        backoff: float,
        backoff_factor: float,
        max_retry_after_secs: float,
    ) -> None:
        if max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if backoff < 0:
            raise ValueError("backoff must be >= 0")
        if backoff_factor <= 0:
            raise ValueError("backoff_factor must be > 0")
        if max_retry_after_secs < 0:
            raise ValueError("max_retry_after_secs must be >= 0")

    def _should_retry_response(self, response: Response) -> bool:
        return response.status_code in self.RETRYABLE_STATUS_CODES

    def _start_request_state(self) -> tuple[int, float, float]:
        return self.__max_retries, self.__backoff, perf_counter()

    def _current_attempt(self, retries_remaining: int) -> int:
        return self.__max_retries - retries_remaining + 1

    def _safe_metric(self, fn: Callable[..., None], *args: Any, **kwargs: Any) -> None:
        try:
            fn(*args, **kwargs)
        except Exception:
            logger.warning("Metric recording failed and was suppressed", exc_info=True)

    def _record_final_metrics(
        self,
        *,
        start_time: float,
        url: str,
        retries_remaining: int,
    ) -> None:
        # Metrics here cover the full logical request, including any retries.
        self._safe_metric(
            self.__metric_service.measure_request_latency, start_time, url
        )
        self._safe_metric(
            self.__metric_service.increase_request_attempt_count,
            dva_url=url,
            attempt_number=self._current_attempt(retries_remaining),
        )

    def _record_attempt_start_metric(self, url: str) -> None:
        self._safe_metric(self.__metric_service.increase_request_count, url)

    def _record_attempt_metrics(self, url: str, response: Response) -> None:
        self._safe_metric(self.__metric_service.measure_response_size, url, response)

    def _advance_retry_state(
        self,
        retries_remaining: int,
        backoff: float,
    ) -> tuple[int, float]:
        return retries_remaining - 1, backoff * self.__backoff_factor

    def _raise_transport_error_with_metrics(
        self,
        *,
        url: str,
        retries_remaining: int,
        start_time: float,
        exception: TransportError,
    ) -> None:
        self._record_final_metrics(
            start_time=start_time,
            url=url,
            retries_remaining=retries_remaining,
        )
        raise exception

    def _log_transport_retry(
        self,
        *,
        url: str,
        retries_remaining: int,
        backoff: float,
        exception: TransportError,
    ) -> float:
        self._log_retry_attempt(
            url=url,
            retries_remaining=retries_remaining,
            backoff=backoff,
            exception=exception,
        )
        return backoff

    def _resolve_response_retry_delay(
        self,
        *,
        url: str,
        response: Response,
        retries_remaining: int,
        backoff: float,
        start_time: float,
    ) -> float | None:
        self._record_attempt_metrics(url, response)

        if not self._should_retry_response(response) or retries_remaining == 0:
            self._record_final_metrics(
                start_time=start_time,
                url=url,
                retries_remaining=retries_remaining,
            )
            return None

        retry_delay = self._resolve_retry_delay(response, backoff)
        self._log_retry_attempt(
            url=url,
            retries_remaining=retries_remaining,
            backoff=retry_delay,
            response=response,
        )
        return retry_delay

    def _extract_retry_error_context(
        self,
        *,
        response: Response | None,
        exception: Exception | None,
    ) -> RetryErrorContext:
        status_code: int | None = None
        error_message: str | None = None

        if response is not None:
            status_code = response.status_code
            error_message = f"HTTP {response.status_code}"

        if exception is None:
            return RetryErrorContext(
                status_code=status_code,
                error_message=error_message,
            )

        error_message = str(exception)
        exception_response = getattr(exception, "response", None)

        if exception_response is not None:
            status_code = getattr(exception_response, "status_code", None)

        return RetryErrorContext(
            status_code=status_code,
            error_message=error_message,
        )

    def _parse_retry_after_header(self, header_value: str) -> float | None:
        trimmed_header_value = header_value.strip()

        try:
            return max(float(trimmed_header_value), 0.0)
        except ValueError:
            pass

        try:
            retry_after_datetime = parsedate_to_datetime(trimmed_header_value)
        except (TypeError, ValueError, IndexError):
            return None

        if retry_after_datetime.tzinfo is None:
            retry_after_datetime = retry_after_datetime.replace(tzinfo=timezone.utc)

        seconds_until_retry = (
            retry_after_datetime - datetime.now(timezone.utc)
        ).total_seconds()
        return max(seconds_until_retry, 0.0)

    def _resolve_retry_delay(self, response: Response, backoff: float) -> float:
        retry_after = response.headers.get("Retry-After")
        if retry_after is None:
            return backoff

        parsed_retry_after = self._parse_retry_after_header(retry_after)
        if parsed_retry_after is None:
            return backoff

        return min(parsed_retry_after, self.__max_retry_after_secs)

    def _log_retry_attempt(
        self,
        url: str,
        backoff: float,
        retries_remaining: int,
        response: Response | None = None,
        exception: Exception | None = None,
    ) -> None:
        effective_attempt_number = self._current_attempt(retries_remaining)
        effective_total_attempts = self.__max_retries + 1
        error_context = self._extract_retry_error_context(
            response=response,
            exception=exception,
        )

        logger.warning(
            "Request failed, retrying: url=%s attempt=%s max_attempts=%s status=%s error=%s backoff_secs=%.2f",
            url,
            effective_attempt_number,
            effective_total_attempts,
            error_context.status_code
            if error_context.status_code is not None
            else "n/a",
            error_context.error_message
            if error_context.error_message is not None
            else "n/a",
            backoff,
        )


class RetryingAsyncClient(RetryingHttpClientBase):
    """Async HTTP client with retry behavior for common HTTP verb calls."""

    @inject.autoparams("metric_service")
    def __init__(
        self,
        async_client: AsyncClient,
        metric_service: MetricService,
        max_retries: int = 3,
        backoff: float = 3,
        backoff_factor: float = 2,
        max_retry_after_secs: float = RetryingHttpClientBase.DEFAULT_MAX_RETRY_AFTER_SECS,
    ) -> None:
        super().__init__(
            metric_service=metric_service,
            max_retries=max_retries,
            backoff=backoff,
            backoff_factor=backoff_factor,
            max_retry_after_secs=max_retry_after_secs,
        )

        self.__async_client = async_client

    async def request(
        self,
        method: str,
        url: str,
        *args: Any,
        **kwargs: Any,
    ) -> Response:
        retries_remaining, current_backoff, start_time = self._start_request_state()

        while True:
            self._record_attempt_start_metric(url)
            try:
                response = await self.__async_client.request(
                    method, url, *args, **kwargs
                )
            except TransportError as exception:
                if retries_remaining == 0:
                    self._raise_transport_error_with_metrics(
                        url=url,
                        retries_remaining=retries_remaining,
                        start_time=start_time,
                        exception=exception,
                    )
                retry_delay = self._log_transport_retry(
                    url=url,
                    retries_remaining=retries_remaining,
                    backoff=current_backoff,
                    exception=exception,
                )
                await self._backoff(retry_delay)
                retries_remaining, current_backoff = self._advance_retry_state(
                    retries_remaining,
                    current_backoff,
                )
                continue

            resolved_retry_delay = self._resolve_response_retry_delay(
                url=url,
                response=response,
                retries_remaining=retries_remaining,
                backoff=current_backoff,
                start_time=start_time,
            )
            if resolved_retry_delay is None:
                return response

            await self._backoff(resolved_retry_delay)
            retries_remaining, current_backoff = self._advance_retry_state(
                retries_remaining,
                current_backoff,
            )

    async def get(self, url: str, *args: Any, **kwargs: Any) -> Response:
        return await self.request("GET", url, *args, **kwargs)

    async def post(
        self, url: str, *args: Any, **kwargs: Any
    ) -> Response:  # pragma: no cover
        return await self.request("POST", url, *args, **kwargs)

    async def put(
        self, url: str, *args: Any, **kwargs: Any
    ) -> Response:  # pragma: no cover
        return await self.request("PUT", url, *args, **kwargs)

    async def patch(
        self, url: str, *args: Any, **kwargs: Any
    ) -> Response:  # pragma: no cover
        return await self.request("PATCH", url, *args, **kwargs)

    async def delete(
        self, url: str, *args: Any, **kwargs: Any
    ) -> Response:  # pragma: no cover
        return await self.request("DELETE", url, *args, **kwargs)

    async def head(
        self, url: str, *args: Any, **kwargs: Any
    ) -> Response:  # pragma: no cover
        return await self.request("HEAD", url, *args, **kwargs)

    async def options(
        self, url: str, *args: Any, **kwargs: Any
    ) -> Response:  # pragma: no cover
        return await self.request("OPTIONS", url, *args, **kwargs)

    async def _backoff(self, duration: float) -> None:
        await async_sleep(duration)


class RetryingSyncClient(RetryingHttpClientBase):
    """Sync HTTP client with retry behavior for common HTTP verb calls."""

    @inject.autoparams("metric_service")
    def __init__(
        self,
        sync_client: Client,
        metric_service: MetricService,
        max_retries: int = 3,
        backoff: float = 3,
        backoff_factor: float = 2,
        max_retry_after_secs: float = RetryingHttpClientBase.DEFAULT_MAX_RETRY_AFTER_SECS,
    ) -> None:
        super().__init__(
            metric_service=metric_service,
            max_retries=max_retries,
            backoff=backoff,
            backoff_factor=backoff_factor,
            max_retry_after_secs=max_retry_after_secs,
        )

        self.__sync_client = sync_client

    def request(
        self,
        method: str,
        url: str,
        *args: Any,
        **kwargs: Any,
    ) -> Response:
        retries_remaining, current_backoff, start_time = self._start_request_state()

        while True:
            self._record_attempt_start_metric(url)
            try:
                response = self.__sync_client.request(method, url, *args, **kwargs)
            except TransportError as exception:
                if retries_remaining == 0:
                    self._raise_transport_error_with_metrics(
                        url=url,
                        retries_remaining=retries_remaining,
                        start_time=start_time,
                        exception=exception,
                    )

                retry_delay = self._log_transport_retry(
                    url=url,
                    retries_remaining=retries_remaining,
                    backoff=current_backoff,
                    exception=exception,
                )

                self._backoff(retry_delay)

                retries_remaining, current_backoff = self._advance_retry_state(
                    retries_remaining,
                    current_backoff,
                )
                continue

            resolved_retry_delay = self._resolve_response_retry_delay(
                url=url,
                response=response,
                retries_remaining=retries_remaining,
                backoff=current_backoff,
                start_time=start_time,
            )
            if resolved_retry_delay is None:
                return response

            self._backoff(resolved_retry_delay)
            retries_remaining, current_backoff = self._advance_retry_state(
                retries_remaining,
                current_backoff,
            )

    def get(self, url: str, *args: Any, **kwargs: Any) -> Response:
        return self.request("GET", url, *args, **kwargs)

    def post(self, url: str, *args: Any, **kwargs: Any) -> Response:
        return self.request("POST", url, *args, **kwargs)

    def put(self, url: str, *args: Any, **kwargs: Any) -> Response:  # pragma: no cover
        return self.request("PUT", url, *args, **kwargs)

    def patch(
        self, url: str, *args: Any, **kwargs: Any
    ) -> Response:  # pragma: no cover
        return self.request("PATCH", url, *args, **kwargs)

    def delete(
        self, url: str, *args: Any, **kwargs: Any
    ) -> Response:  # pragma: no cover
        return self.request("DELETE", url, *args, **kwargs)

    def head(self, url: str, *args: Any, **kwargs: Any) -> Response:  # pragma: no cover
        return self.request("HEAD", url, *args, **kwargs)

    def options(
        self, url: str, *args: Any, **kwargs: Any
    ) -> Response:  # pragma: no cover
        return self.request("OPTIONS", url, *args, **kwargs)

    def _backoff(self, duration: float) -> None:
        blocking_sleep(duration)
