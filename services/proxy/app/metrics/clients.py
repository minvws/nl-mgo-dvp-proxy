from abc import ABC, abstractmethod
from datetime import timedelta


class MetricClient(ABC):  # pragma: no cover
    @abstractmethod
    def incr(self, stat: str, count: int = 1, rate: float = 1) -> None:
        pass

    @abstractmethod
    def timing(self, stat: str, delta: int | float | timedelta) -> None:
        pass


class NoOpMetricClient(MetricClient):  # pragma: no cover
    """Metric client no-op implementation so local development environments need not set up a functioning metric service"""

    def incr(self, stat: str, count: int = 1, rate: float = 1) -> None:
        """MetricClient@incr stub"""
        pass

    def timing(self, stat: str, delta: int | float | timedelta) -> None:
        """MetricClient@timing stub"""
        pass
