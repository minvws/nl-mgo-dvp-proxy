import inject
from fastapi.testclient import TestClient

from app.circuitbreaker.services import CircuitBreaker


def test_it_is_bound_to_the_container(test_client: TestClient) -> None:
    breaker = inject.instance(CircuitBreaker)

    assert isinstance(breaker, CircuitBreaker)


def test_it_is_configured_correctly(test_client: TestClient) -> None:
    breaker = inject.instance(CircuitBreaker)

    assert breaker.fail_max == 5
    assert breaker.reset_timeout == 60
