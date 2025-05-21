import inject
from fastapi.testclient import TestClient

from app.circuitbreaker.services import CircuitBreakerService


def test_it_is_bound_to_the_container(test_client: TestClient) -> None:
    breaker = inject.instance(CircuitBreakerService)

    assert isinstance(breaker, CircuitBreakerService)


def test_it_is_configured_correctly(test_client: TestClient) -> None:
    breaker = inject.instance(CircuitBreakerService)

    assert breaker.fail_max == 5
    assert breaker.reset_timeout == 60
