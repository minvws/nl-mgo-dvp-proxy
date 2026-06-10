import logging
from random import randint
from typing import Any

import pytest
from httpx import Client, ConnectError, Request, Response
from pytest_mock import MockerFixture

from app.forwarding.client import RetryingSyncClient
from app.metrics.service import MetricService
from tests.utils import assert_captured_logs

acceptable_status_codes = [200, 201, 204, 301, 302, 401, 404]
unacceptable_status_codes = [429, 500, 502, 503, 504]


class TestRetryingSyncClient:
    @pytest.mark.parametrize(
        ("config", "expected_error"),
        [
            ({"max_retries": -1}, "max_retries must be >= 0"),
            ({"backoff": -5.0}, "backoff must be >= 0"),
            ({"backoff_factor": 0}, "backoff_factor must be > 0"),
            ({"max_retry_after_secs": -1}, "max_retry_after_secs must be >= 0"),
        ],
    )
    def test_invalid_retry_config_raises_value_error(
        self,
        mocker: MockerFixture,
        config: dict[str, Any],
        expected_error: str,
    ) -> None:
        with pytest.raises(ValueError, match=expected_error):
            RetryingSyncClient(
                sync_client=mocker.Mock(Client),
                metric_service=mocker.Mock(spec=MetricService),
                **config,
            )

    @pytest.mark.parametrize("status_code", acceptable_status_codes)
    def test_no_retries_if_response_status_acceptable(
        self,
        mocker: MockerFixture,
        status_code: int,
    ) -> None:
        client = mocker.Mock(Client)
        client.request = mocker.Mock(return_value=Response(status_code=status_code))

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=mocker.Mock(spec=MetricService),
            max_retries=randint(1, 10),
            backoff=0.5,
            backoff_factor=1.5,
        )

        response = retrying_sync_client.get("http://test")

        assert client.request.call_count == 1
        assert response.status_code == status_code

    def test_post_delegates_to_request_with_post_method(
        self,
        mocker: MockerFixture,
    ) -> None:
        client = mocker.Mock(Client)
        client.request = mocker.Mock(return_value=Response(status_code=200))

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=mocker.Mock(spec=MetricService),
            max_retries=0,
            backoff=0.01,
            backoff_factor=1.0,
        )

        response = retrying_sync_client.post(
            "http://test",
            data={"grant_type": "authorization_code"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        assert response.status_code == 200
        client.request.assert_called_once_with(
            "POST",
            "http://test",
            data={"grant_type": "authorization_code"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    @pytest.mark.parametrize("status_code", unacceptable_status_codes)
    def test_retries_if_response_status_not_acceptable(
        self,
        mocker: MockerFixture,
        status_code: int,
    ) -> None:
        max_retries = randint(1, 10)
        client = mocker.Mock(Client)
        client.request = mocker.Mock(return_value=Response(status_code=status_code))

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=mocker.Mock(spec=MetricService),
            max_retries=max_retries,
            backoff=0.01,
            backoff_factor=1.0,
        )

        response = retrying_sync_client.get("http://test")

        assert client.request.call_count == max_retries + 1
        assert response.status_code == status_code

    @pytest.mark.parametrize("status_code", unacceptable_status_codes)
    def test_one_call_made_if_no_retries_configured(
        self,
        mocker: MockerFixture,
        status_code: int,
    ) -> None:
        client = mocker.Mock(Client)
        client.request = mocker.Mock(return_value=Response(status_code=status_code))

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=mocker.Mock(spec=MetricService),
            max_retries=0,
            backoff=0.01,
            backoff_factor=1.0,
        )

        response = retrying_sync_client.get("http://test")

        assert client.request.call_count == 1
        assert response.status_code == status_code

    def test_does_not_retry_non_retryable_exception(
        self,
        mocker: MockerFixture,
    ) -> None:
        client = mocker.Mock(Client)
        client.request = mocker.Mock(side_effect=ValueError("Something went wrong"))
        mock_sleep = mocker.Mock()
        mocker.patch("app.forwarding.client.blocking_sleep", mock_sleep)

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=mocker.Mock(spec=MetricService),
            max_retries=3,
            backoff=0.01,
            backoff_factor=1.0,
        )

        with pytest.raises(ValueError, match="Something went wrong"):
            retrying_sync_client.get("http://test")

        assert client.request.call_count == 1
        mock_sleep.assert_not_called()

    def test_retries_on_retryable_transport_exception(
        self,
        mocker: MockerFixture,
    ) -> None:
        request = Request("GET", "http://test")
        client = mocker.Mock(Client)
        client.request = mocker.Mock(
            side_effect=[
                ConnectError("Connection aborted", request=request),
                Response(status_code=200),
            ]
        )
        mock_sleep = mocker.Mock()
        mocker.patch("app.forwarding.client.blocking_sleep", mock_sleep)

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=mocker.Mock(spec=MetricService),
            max_retries=1,
            backoff=0.02,
            backoff_factor=2.0,
        )

        response = retrying_sync_client.get("http://test")

        assert response.status_code == 200
        assert client.request.call_count == 2
        mock_sleep.assert_called_once_with(0.02)

    def test_raises_transport_error_when_retries_exhausted(
        self,
        mocker: MockerFixture,
    ) -> None:
        request = Request("GET", "http://test")
        client = mocker.Mock(Client)
        client.request = mocker.Mock(
            side_effect=ConnectError("Connection refused", request=request)
        )
        mock_sleep = mocker.Mock()
        mocker.patch("app.forwarding.client.blocking_sleep", mock_sleep)

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=mocker.Mock(spec=MetricService),
            max_retries=2,
            backoff=0.02,
            backoff_factor=2.0,
        )

        with pytest.raises(ConnectError):
            retrying_sync_client.get("http://test")

        assert client.request.call_count == 3
        assert mock_sleep.call_count == 2

    def test_backoff_factor_increases_backoff_on_each_retry(
        self,
        mocker: MockerFixture,
    ) -> None:
        client = mocker.Mock(Client)
        client.request = mocker.Mock(return_value=Response(status_code=500))
        mock_sleep = mocker.Mock()
        mocker.patch("app.forwarding.client.blocking_sleep", mock_sleep)

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=mocker.Mock(spec=MetricService),
            max_retries=4,
            backoff=0.02,
            backoff_factor=2.0,
        )

        retrying_sync_client.get("http://test")

        assert [call.args[0] for call in mock_sleep.call_args_list] == [
            0.02,
            0.04,
            0.08,
            0.16,
        ]

    def test_retry_after_header_overrides_backoff(
        self,
        mocker: MockerFixture,
    ) -> None:
        client = mocker.Mock(Client)
        client.request = mocker.Mock(
            side_effect=[
                Response(status_code=429, headers={"Retry-After": "0.5"}),
                Response(status_code=200),
            ]
        )
        mock_sleep = mocker.Mock()
        mocker.patch("app.forwarding.client.blocking_sleep", mock_sleep)

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=mocker.Mock(spec=MetricService),
            max_retries=1,
            backoff=0.02,
            backoff_factor=2.0,
        )

        response = retrying_sync_client.get("http://test")

        assert response.status_code == 200
        mock_sleep.assert_called_once_with(0.5)

    def test_invalid_retry_after_header_falls_back_to_backoff(
        self,
        mocker: MockerFixture,
    ) -> None:
        client = mocker.Mock(Client)
        client.request = mocker.Mock(
            side_effect=[
                Response(status_code=429, headers={"Retry-After": "invalid-header"}),
                Response(status_code=200),
            ]
        )
        mock_sleep = mocker.Mock()
        mocker.patch("app.forwarding.client.blocking_sleep", mock_sleep)

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=mocker.Mock(spec=MetricService),
            max_retries=1,
            backoff=0.02,
            backoff_factor=2.0,
        )

        response = retrying_sync_client.get("http://test")

        assert response.status_code == 200
        mock_sleep.assert_called_once_with(0.02)

    def test_retry_after_header_is_capped_at_max_retry_after_secs(
        self,
        mocker: MockerFixture,
    ) -> None:
        client = mocker.Mock(Client)
        client.request = mocker.Mock(
            side_effect=[
                Response(status_code=429, headers={"Retry-After": "300"}),
                Response(status_code=200),
            ]
        )
        mock_sleep = mocker.Mock()
        mocker.patch("app.forwarding.client.blocking_sleep", mock_sleep)

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=mocker.Mock(spec=MetricService),
            max_retries=1,
            backoff=0.02,
            backoff_factor=2.0,
            max_retry_after_secs=5.0,
        )

        response = retrying_sync_client.get("http://test")

        assert response.status_code == 200
        mock_sleep.assert_called_once_with(5.0)

    def test_retry_after_http_date_without_timezone_is_parsed(
        self,
        mocker: MockerFixture,
    ) -> None:
        client = mocker.Mock(Client)
        client.request = mocker.Mock(
            side_effect=[
                Response(
                    status_code=429,
                    headers={"Retry-After": "Wed, 21 Oct 2099 07:28:00"},
                ),
                Response(status_code=200),
            ]
        )
        mock_sleep = mocker.Mock()
        mocker.patch("app.forwarding.client.blocking_sleep", mock_sleep)

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=mocker.Mock(spec=MetricService),
            max_retries=1,
            backoff=0.5,
            backoff_factor=2.0,
            max_retry_after_secs=0.0,
        )

        response = retrying_sync_client.get("http://test")

        assert response.status_code == 200
        mock_sleep.assert_called_once_with(0.0)

    def test_retry_after_http_date_with_timezone_is_parsed(
        self,
        mocker: MockerFixture,
    ) -> None:
        client = mocker.Mock(Client)
        client.request = mocker.Mock(
            side_effect=[
                Response(
                    status_code=429,
                    headers={"Retry-After": "Wed, 21 Oct 2099 07:28:00 GMT"},
                ),
                Response(status_code=200),
            ]
        )
        mock_sleep = mocker.Mock()
        mocker.patch("app.forwarding.client.blocking_sleep", mock_sleep)

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=mocker.Mock(spec=MetricService),
            max_retries=1,
            backoff=0.5,
            backoff_factor=2.0,
            max_retry_after_secs=0.0,
        )

        response = retrying_sync_client.get("http://test")

        assert response.status_code == 200
        mock_sleep.assert_called_once_with(0.0)

    def test_metrics_failure_does_not_affect_request(
        self,
        mocker: MockerFixture,
    ) -> None:
        client = mocker.Mock(Client)
        client.request = mocker.Mock(return_value=Response(status_code=200))

        metric_service = mocker.Mock(spec=MetricService)
        metric_service.increase_request_count.side_effect = Exception("metric failed")

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=metric_service,
            max_retries=0,
            backoff=0.01,
            backoff_factor=1.0,
        )

        response = retrying_sync_client.get("http://test")

        assert response.status_code == 200

    def test_logs_retry_context_on_retryable_response(
        self,
        mocker: MockerFixture,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        client = mocker.Mock(Client)
        client.request = mocker.Mock(
            side_effect=[
                Response(status_code=503),
                Response(status_code=200),
            ]
        )
        mocker.patch("app.forwarding.client.blocking_sleep", mocker.Mock())

        retrying_sync_client = RetryingSyncClient(
            sync_client=client,
            metric_service=mocker.Mock(spec=MetricService),
            max_retries=1,
            backoff=0.01,
            backoff_factor=2.0,
        )

        target_logger = logging.getLogger("app.forwarding.client")
        target_logger.addHandler(caplog.handler)
        caplog.set_level(logging.WARNING, logger="app.forwarding.client")

        try:
            response = retrying_sync_client.get("http://test")
        finally:
            target_logger.removeHandler(caplog.handler)

        assert response.status_code == 200
        assert_captured_logs(
            caplog,
            [
                (
                    "Request failed, retrying: url=http://test attempt=1 max_attempts=2 status=503 error=HTTP 503 backoff_secs=0.01",
                    logging.WARNING,
                )
            ],
        )
