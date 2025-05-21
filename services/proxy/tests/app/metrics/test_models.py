from sys import maxsize
from typing import Any, Dict, List

import pytest

from app.metrics.models import BucketCounter, ResponseSizeBucket


class TestBucketCounter:
    @pytest.fixture
    def buckets(self) -> List[Dict[str, int]]:
        return [
            {"min": 0, "max": 100},
            {"min": 101, "max": 500},
            {"min": 501, "max": 1000},
        ]

    @pytest.fixture
    def bucket_counter(self, buckets: List[Dict[str, int]]) -> BucketCounter:
        return BucketCounter(buckets)

    def test_determine_bucket_within_range(self, bucket_counter: BucketCounter) -> None:
        test_cases = [
            (50, "size.0-100"),
            (150, "size.101-500"),
            (750, "size.501-1000"),
        ]
        for size, expected in test_cases:
            assert bucket_counter.determine_bucket("size", size) == expected

    def test_determine_bucket_edge_cases(self, bucket_counter: BucketCounter) -> None:
        test_cases = [
            (0, "size.0-100"),
            (100, "size.0-100"),
            (101, "size.101-500"),
            (500, "size.101-500"),
            (501, "size.501-1000"),
            (1000, "size.501-1000"),
        ]
        for size, expected in test_cases:
            assert bucket_counter.determine_bucket("size", size) == expected

    def test_determine_bucket_out_of_range(self, bucket_counter: BucketCounter) -> None:
        assert bucket_counter.determine_bucket("size", 1500) == "size.501-1000"

    def test_init_of_response_size_bucket(self) -> None:
        expected_buckets: List[Dict[str, Any]] = [
            {"min": 0, "max": 100},
            {"min": 101, "max": 500},
            {"min": 501, "max": 1000},
            {"min": 1001, "max": 5000},
            {"min": 5001, "max": 10000},
            {"min": 10001, "max": 30000},
            {"min": 30001, "max": maxsize},
        ]
        bucket = ResponseSizeBucket()
        assert bucket.buckets == expected_buckets


class TestResponseSizeBucket:
    def test_bucket_initialization(self) -> None:
        bucket = ResponseSizeBucket()
        expected_buckets: List[Dict[str, Any]] = [
            {"min": 0, "max": 100},
            {"min": 101, "max": 500},
            {"min": 501, "max": 1000},
            {"min": 1001, "max": 5000},
            {"min": 5001, "max": 10000},
            {"min": 10001, "max": 30000},
            {"min": 30001, "max": maxsize},
        ]
        assert bucket.buckets == expected_buckets

    def test_determine_bucket(self) -> None:
        bucket = ResponseSizeBucket()
        metric_key = "response.size"
        size_in_kb = 150
        expected_metric = f"{metric_key}.101-500"
        actual_metric = bucket.determine_bucket(metric_key, size_in_kb)
        assert actual_metric == expected_metric
