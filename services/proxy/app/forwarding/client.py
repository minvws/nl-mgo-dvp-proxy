from logging import Logger
from time import time
from typing import Any

import inject
from anyio import sleep
from httpx import AsyncClient, Response

from app.config.models import AppConfig
from app.metrics.service import MetricService


class AsyncClientRetryDecorator:
    @inject.autoparams("app_config", "metric_service", "logger")
    def __init__(
        self,
        async_client: AsyncClient,
        app_config: AppConfig,
        metric_service: MetricService,
        logger: Logger,
    ) -> None:
        self.async_client = async_client
        self.retry_config = app_config.retry
        self.metric_service = metric_service
        self.logger = logger

    async def get(self, url: str, *args: Any, **kwargs: Any) -> Response:
        retries_remaining = self.retry_config.max_retries
        backoff = self.retry_config.backoff
        start_time = time()

        intercepted_exception = None
        while True:
            try:
                self.metric_service.increase_request_count(str(url))
                response = await self.async_client.get(url, *args, **kwargs)
                self.metric_service.measure_response_size(str(url), response)
                if response.status_code < 500 or retries_remaining == 0:
                    break
            except Exception as exception:
                if retries_remaining == 0:
                    intercepted_exception = exception
                    break

            self.logger.debug(f"Backing off for %.2f seconds...", backoff)
            await self._backoff(backoff)

            retries_remaining -= 1
            backoff *= self.retry_config.backoff_factor

        self.metric_service.measure_request_latency(start_time, str(url))

        self.metric_service.increase_request_attempt_count(
            dva_url=str(url),
            attempt_number=self.retry_config.max_retries - retries_remaining + 1,
        )

        if intercepted_exception is not None:
            raise intercepted_exception

        return response

    async def _backoff(self, duration: float) -> None:  # pragma: no cover
        await sleep(duration)
