from random import randint
from typing import Any

import pytest
from httpx import AsyncClient, Response
from pytest import mark
from pytest_mock import MockerFixture

from app.config.models import RetryConfig
from app.forwarding.client import AsyncClientRetryDecorator
from app.metrics.service import MetricService
from tests.utils import load_app_config

acceptable_status_codes = [200, 201, 204, 301, 302, 401, 404]
""" List of status codes that are considered acceptable, meaning a retry is not required. """
unacceptable_status_codes = [500, 502, 503]
""" List of status codes that are considered errors, resulting in a retry. """


@mark.anyio
class TestAsyncClientRetryDecorator:
    @mark.parametrize("status_code", acceptable_status_codes)
    async def test_no_retries_if_response_status_acceptable(
        self,
        mocker: MockerFixture,
        status_code: int,
    ) -> None:
        mock_response = mocker.AsyncMock(return_value=Response(status_code=status_code))

        client = mocker.Mock(AsyncClient)
        client.get = mock_response

        config = load_app_config()
        config.retry = RetryConfig(
            max_retries=randint(1, 10),
            backoff=0.5,
            backoff_factor=1.5,
        )

        async_client_retry_decorator = AsyncClientRetryDecorator(
            async_client=client,
            app_config=config,
            metric_service=mocker.Mock(spec=MetricService),
        )
        response = await async_client_retry_decorator.get("http://test")

        assert mock_response.call_count == 1
        assert response.status_code == status_code

    @mark.parametrize("status_code", acceptable_status_codes)
    async def test_metrics_if_response_status_acceptable(
        self,
        mocker: MockerFixture,
        status_code: int,
    ) -> None:
        target_url = "http://test"

        mock_response = mocker.AsyncMock(return_value=Response(status_code=status_code))

        client = mocker.Mock(AsyncClient)
        client.get = mock_response

        metric_service = mocker.Mock(spec=MetricService)

        config = load_app_config()
        config.retry = RetryConfig(
            max_retries=randint(1, 10),
            backoff=0.01,
            backoff_factor=1.0,
        )

        async_client_retry_decorator = AsyncClientRetryDecorator(
            async_client=client,
            app_config=config,
            metric_service=metric_service,
        )

        await async_client_retry_decorator.get(target_url)

        metric_service.increase_request_attempt_count.assert_called_once_with(
            dva_url=target_url, attempt_number=1
        )
        metric_service.increase_request_count.assert_called_once()
        metric_service.measure_request_latency.assert_called_once()
        metric_service.measure_response_size.assert_called_once()

    @mark.parametrize("status_code", unacceptable_status_codes)
    async def test_retries_if_response_status_not_acceptable(
        self,
        mocker: MockerFixture,
        status_code: int,
    ) -> None:
        max_retries = randint(1, 10)

        mock_response = mocker.AsyncMock(return_value=Response(status_code=status_code))

        client = AsyncClient()
        mocker.patch.object(client, "get", mock_response)

        config = load_app_config()
        config.retry = RetryConfig(
            max_retries=max_retries,
            backoff=0.01,
            backoff_factor=1.0,
        )

        async_client_retry_decorator = AsyncClientRetryDecorator(
            async_client=client,
            app_config=config,
            metric_service=mocker.Mock(spec=MetricService),
        )

        response = await async_client_retry_decorator.get("http://test")

        assert mock_response.call_count == max_retries + 1
        assert response.status_code == status_code

    @mark.parametrize("status_code", unacceptable_status_codes)
    async def test_metrics_if_response_status_not_acceptable(
        self,
        mocker: MockerFixture,
        status_code: int,
    ) -> None:
        target_url = "http://test"
        max_retries = randint(1, 10)
        expected_attempt_count = max_retries + 1

        mock_response = mocker.AsyncMock(return_value=Response(status_code=status_code))

        client = mocker.Mock(AsyncClient)
        client.get = mock_response

        config = load_app_config()
        config.retry = RetryConfig(
            max_retries=max_retries,
            backoff=0.01,
            backoff_factor=1.0,
        )

        metric_service = mocker.Mock(spec=MetricService)

        async_client_retry_decorator = AsyncClientRetryDecorator(
            async_client=client,
            app_config=config,
            metric_service=metric_service,
        )

        await async_client_retry_decorator.get(target_url)

        metric_service.measure_request_latency.assert_called_once()
        metric_service.increase_request_attempt_count.assert_called_once_with(
            dva_url=target_url, attempt_number=expected_attempt_count
        )

        assert (
            metric_service.increase_request_count.call_count == expected_attempt_count
        )
        assert metric_service.measure_response_size.call_count == expected_attempt_count

    @mark.parametrize("status_code", unacceptable_status_codes)
    async def test_one_call_made_if_no_retries_configured(
        self,
        mocker: MockerFixture,
        status_code: int,
    ) -> None:
        mock_response = mocker.AsyncMock(return_value=Response(status_code=status_code))
        max_retries = 0

        client = mocker.Mock(AsyncClient)
        client.get = mock_response

        config = load_app_config()
        config.retry = RetryConfig(
            max_retries=max_retries,
            backoff=0.01,
            backoff_factor=1.0,
        )

        async_client_retry_decorator = AsyncClientRetryDecorator(
            async_client=client,
            app_config=config,
            metric_service=mocker.Mock(spec=MetricService),
        )
        response = await async_client_retry_decorator.get("http://test")

        assert mock_response.call_count == 1
        assert response.status_code == status_code

    async def test_backoff_factor_increases_backoff_on_each_retry(
        self,
        mocker: MockerFixture,
    ) -> None:
        mock_response = mocker.AsyncMock(return_value=Response(status_code=500))
        mock_backoff = mocker.AsyncMock()
        max_retries = 4
        backoff = 0.02
        backoff_factor = 2.0

        client = mocker.Mock(AsyncClient)
        client.get = mock_response

        config = load_app_config()
        config.retry = RetryConfig(
            max_retries=max_retries,
            backoff=backoff,
            backoff_factor=backoff_factor,
        )

        async_client_retry_decorator = AsyncClientRetryDecorator(
            async_client=client,
            app_config=config,
            metric_service=mocker.Mock(spec=MetricService),
        )
        async_client_retry_decorator._backoff = mock_backoff

        await async_client_retry_decorator.get("http://test")

        assert [call.args[0] for call in mock_backoff.call_args_list] == [
            0.02,
            0.04,
            0.08,
            0.16,
        ]

    async def test_return_bad_gateway_response_when_an_exception_was_raised_while_there_are_no_retries_remaining(
        self,
        mocker: MockerFixture,
    ) -> None:
        async def mock_response(*args: Any, **kwargs: Any) -> None:
            _ = args, kwargs
            raise Exception("Something went wrong")

        max_retries = 1

        client = mocker.Mock(AsyncClient)
        client.get = mock_response

        config = load_app_config()
        config.retry = RetryConfig(
            max_retries=max_retries,
            backoff=0.02,
            backoff_factor=2.0,
        )

        async_client_retry_decorator = AsyncClientRetryDecorator(
            async_client=client,
            app_config=config,
            metric_service=mocker.Mock(spec=MetricService),
        )
        async_client_retry_decorator._backoff = mocker.AsyncMock()

        with pytest.raises(Exception) as exception_info:
            await async_client_retry_decorator.get("http://test")

        assert exception_info.exconly() == "Exception: Something went wrong"
