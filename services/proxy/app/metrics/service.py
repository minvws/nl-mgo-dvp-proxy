import time
from urllib import parse as urlparse

import inject
from httpx import Response

from .clients import MetricClient
from .enums import Metrics
from .models import ResponseSizeBucket


class MetricService:
    @inject.autoparams()
    def __init__(self, metric_client: MetricClient) -> None:
        self.metric_client = metric_client

    def sanitize_url(self, url: str) -> str:
        parsed_url = urlparse.urlparse(url)
        hostname = parsed_url.hostname

        if hostname is None:
            raise ValueError(f"Could not derive hostname from url: {url}")

        return hostname.replace(".", "_")

    def measure_request_latency(self, start_time: float, dva_url: str) -> None:
        latency = int((time.time() - start_time) * 1000)
        key = Metrics.DVA_REQUEST_LATENCY.format_key(
            {
                "dva": self.sanitize_url(dva_url),
            },
        )
        self.metric_client.timing(key, latency)

    def increase_request_count(self, dva_url: str) -> None:
        key = Metrics.DVA_REQUEST_COUNT.format_key(
            {
                "dva": self.sanitize_url(dva_url),
            },
        )

        self.metric_client.incr(key)

    def increase_request_attempt_count(self, dva_url: str, attempt_number: int) -> None:
        key = Metrics.DVA_REQUEST_ATTEMPT_COUNT.format_key(
            {
                "dva": self.sanitize_url(dva_url),
                "attempt_number": attempt_number,
            },
        )

        self.metric_client.incr(key)

    def measure_response_size(self, dva_url: str, response: Response) -> None:
        key = Metrics.DVA_RESPONSE_SIZE.format_key(
            {
                "dva": self.sanitize_url(dva_url),
            },
        )

        size_in_kb = len(response.content) / 1024
        bucket = ResponseSizeBucket().determine_bucket(key, size_in_kb)

        self.metric_client.incr(bucket)
