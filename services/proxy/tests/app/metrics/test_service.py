import pytest
from httpx import Response
from pytest_mock import MockerFixture

from app.metrics.clients import NoOpMetricClient
from app.metrics.models import ResponseSizeBucket
from app.metrics.service import MetricService


class TestMetricService:
    @pytest.fixture
    def metric_service(self) -> MetricService:
        metric_service: MetricService = MetricService(metric_client=NoOpMetricClient())
        return metric_service

    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://example.com/?param=value", "example_com"),
            ("https://www.example.com", "www_example_com"),
            ("https://subdomain.example.com", "subdomain_example_com"),
            ("https://example.com#fragment", "example_com"),
            ("https://example.com/path/to/resource", "example_com"),
            ("https://example.com?param1=value1&param2=value2", "example_com"),
            ("https://example.com/path/", "example_com"),
            ("https://example.com", "example_com"),
            (
                "https://foo-bar.foo.bar.example.com/",
                "foo-bar_foo_bar_example_com",
            ),
            (
                "https://foo.bar.example.com/",
                "foo_bar_example_com",
            ),
        ],
    )
    def test_sanitize_url(
        self,
        url: str,
        expected: str,
        metric_service: MetricService,
    ) -> None:
        assert metric_service.sanitize_url(url) == expected

    def test_measure_request_latency_timing_with_correct_parameters(
        self, mocker: MockerFixture, metric_service: MetricService
    ) -> None:
        mocked_start_time = 1000
        dva_url = "https://test.dva.key"
        mocked_current_time = 1001
        expected_latency = 1000

        timing_spy = mocker.spy(NoOpMetricClient, "timing")
        mocker.patch("time.time", return_value=mocked_current_time)

        metric_service.measure_request_latency(
            start_time=mocked_start_time, dva_url=dva_url
        )

        timing_spy.assert_called_once_with(
            metric_service.metric_client,
            "test_dva_key.request.latency",
            expected_latency,
        )

    def test_increase_request_count(
        self, mocker: MockerFixture, metric_service: MetricService
    ) -> None:
        dva_url = "https://test.dva.key"

        incr_spy = mocker.spy(NoOpMetricClient, "incr")

        metric_service.increase_request_count(dva_url)

        incr_spy.assert_called_once_with(
            metric_service.metric_client, "test_dva_key.request.count"
        )

    def test_increase_request_attempt_count(
        self, mocker: MockerFixture, metric_service: MetricService
    ) -> None:
        dva_url = "https://test.dva.key"
        attempt_number = 3

        incr_spy = mocker.spy(NoOpMetricClient, "incr")

        metric_service.increase_request_attempt_count(dva_url, attempt_number)

        incr_spy.assert_called_once_with(
            metric_service.metric_client, "test_dva_key.request.attempt_count.3"
        )

    def test_measure_response_size(
        self, mocker: MockerFixture, metric_service: MetricService
    ) -> None:
        dva_url = "https://test.dva.key"
        response = Response(200, content=b" " * 1025)

        incr_spy = mocker.spy(NoOpMetricClient, "incr")
        mocker.patch.object(
            ResponseSizeBucket,
            "determine_bucket",
            return_value="test_dva_key.response.size.1-1024",
        )

        metric_service.measure_response_size(dva_url, response)

        incr_spy.assert_called_once_with(
            metric_service.metric_client, "test_dva_key.response.size.1-1024"
        )

    def test_it_raises_error_when_no_hostname_can_be_derived_from_url(
        self,
        metric_service: MetricService,
    ) -> None:
        url = "https://"

        with pytest.raises(ValueError):
            metric_service.sanitize_url(url)
