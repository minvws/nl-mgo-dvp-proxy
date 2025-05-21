from typing import Any

import pytest
from pytest_mock import MockerFixture

from app.circuitbreaker.models import Circuit, CircuitState
from app.circuitbreaker.repositories import (
    InMemoryCircuitStateRepository,
    RedisCircuitStateRepository,
)


@pytest.fixture
def repository() -> InMemoryCircuitStateRepository:
    return InMemoryCircuitStateRepository()


@pytest.fixture
def mock_redis(mocker: MockerFixture) -> Any:
    return mocker.Mock()


@pytest.fixture
def redis_repository(mock_redis: MockerFixture) -> Any:
    return RedisCircuitStateRepository(redis=mock_redis)


def test_in_memory_repository_can_save_and_get(
    repository: InMemoryCircuitStateRepository,
) -> None:
    circuit = Circuit(id="https://example.com/api/resource1")
    repository.save_circuit(circuit)

    saved_circuit = repository.get_circuit("https://example.com/api/resource1")
    assert saved_circuit == circuit


def test_in_memory_repository_default_circuit(
    repository: InMemoryCircuitStateRepository,
) -> None:
    circuit = repository.get_circuit("https://example.com/api/resource1")
    assert circuit.state == CircuitState.CLOSED
    assert circuit.fail_count == 0


def test_redis_get_circuit_existing(
    redis_repository: RedisCircuitStateRepository, mock_redis: Any
) -> None:
    identifier = "https://example.com/api/resource1"
    mock_circuit = Circuit(
        id=identifier, state=CircuitState.CLOSED, fail_count=0, last_failure_time=0.0
    )
    mock_redis.get.return_value = mock_circuit.model_dump_json()

    circuit = redis_repository.get_circuit(identifier)

    mock_redis.get.assert_called_once_with(identifier)
    assert circuit.id == mock_circuit.id
    assert circuit.state == mock_circuit.state
    assert circuit.fail_count == mock_circuit.fail_count
    assert circuit.last_failure_time == mock_circuit.last_failure_time


def test_redis_get_circuit_not_existing(
    redis_repository: RedisCircuitStateRepository, mock_redis: Any
) -> None:
    identifier = "https://example.com/api/resource2"
    mock_redis.get.return_value = None

    circuit = redis_repository.get_circuit(identifier)

    mock_redis.get.assert_called_once_with(identifier)
    assert circuit.id == identifier
    assert circuit.state == CircuitState.CLOSED
    assert circuit.fail_count == 0


def test_redis_save_circuit_success(
    redis_repository: RedisCircuitStateRepository, mock_redis: Any
) -> None:
    circuit = Circuit(id="https://example.com/api/resource1", state=CircuitState.OPEN)

    redis_repository.save_circuit(circuit)

    mock_redis.set.assert_called_once_with(circuit.id, circuit.model_dump_json())


def test_redis_save_circuit_failure(
    redis_repository: RedisCircuitStateRepository, mock_redis: Any
) -> None:
    circuit = Circuit(id="https://example.com/api/resource1", state=CircuitState.OPEN)
    mock_redis.set.side_effect = Exception("Redis error")

    with pytest.raises(
        Exception, match=f"Error saving circuit {circuit.id}: Redis error"
    ):
        redis_repository.save_circuit(circuit)

    mock_redis.set.assert_called_once_with(circuit.id, circuit.model_dump_json())
