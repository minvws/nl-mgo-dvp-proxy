from abc import ABC
from sys import maxsize


class BucketCounter(ABC):
    def __init__(self, buckets: list[dict[str, int]]) -> None:
        """
        Initialize with a list of buckets. Each bucket is a dict with 'min' and 'max' keys.
        """
        self.buckets = buckets

    def determine_bucket(self, key: str, value: float) -> str:
        """
        Get of the bucket that the value falls into.
        """
        for bucket in self.buckets:
            if bucket["min"] <= value <= bucket["max"]:
                return f"{key}.{bucket['min']}-{bucket['max']}"

        return f"{key}.{self.buckets[-1]['min']}-{self.buckets[-1]['max']}"


class ResponseSizeBucket(BucketCounter):
    def __init__(self) -> None:
        self.buckets = [
            {"min": 0, "max": 100},
            {"min": 101, "max": 500},
            {"min": 501, "max": 1000},
            {"min": 1001, "max": 5000},
            {"min": 5001, "max": 10000},
            {"min": 10001, "max": 30000},
            {"min": 30001, "max": maxsize},
        ]
