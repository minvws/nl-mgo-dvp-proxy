import time
from logging import Logger
from typing import Any

import pytest
from pytest_mock import MockerFixture

from app.circuitbreaker.models import Circuit, CircuitOpenException, CircuitState
from app.circuitbreaker.repositories import InMemoryCircuitStateRepository
from app.circuitbreaker.services import CircuitBreakerService


@pytest.fixture
def repository() -> InMemoryCircuitStateRepository:
    return InMemoryCircuitStateRepository()


@pytest.fixture
def circuit_breaker(
    mocker: MockerFixture,
    repository: InMemoryCircuitStateRepository,
) -> Any:
    return CircuitBreakerService(
        repository,
        mocker.Mock(Logger),
        fail_max=3,
        reset_timeout=1,
    )


@pytest.fixture
def closed_circuit(repository: InMemoryCircuitStateRepository) -> Circuit:
    circuit = Circuit(
        id="https://example.com/api/resource1", state=CircuitState.CLOSED, fail_count=0
    )
    repository.save_circuit(circuit)
    return circuit


@pytest.fixture
def open_circuit(repository: InMemoryCircuitStateRepository) -> Circuit:
    circuit = Circuit(
        id="https://example.com/api/resource1", state=CircuitState.OPEN, fail_count=3
    )
    repository.save_circuit(circuit)
    return circuit


@pytest.mark.asyncio
async def test_circuit_breaker_success(
    mocker: Any, circuit_breaker: CircuitBreakerService, closed_circuit: Circuit
) -> None:
    url = closed_circuit.id
    func = mocker.AsyncMock(return_value="Success")

    result = await circuit_breaker.call(url, func)
    assert result == "Success"
    func.assert_called_once()
    circuit = circuit_breaker.repository.get_circuit(url)
    assert circuit.state == CircuitState.CLOSED
    assert circuit.fail_count == 0


@pytest.mark.asyncio
async def test_circuit_breaker_failure(
    mocker: Any, circuit_breaker: CircuitBreakerService, closed_circuit: Circuit
) -> None:
    url = closed_circuit.id
    func = mocker.AsyncMock(side_effect=Exception("Error"))

    with pytest.raises(Exception):
        await circuit_breaker.call(url, func)

    circuit = circuit_breaker.repository.get_circuit(url)
    assert circuit.state == CircuitState.CLOSED
    assert circuit.fail_count == 1


@pytest.mark.asyncio
async def test_circuit_breaker_opens_after_failures(
    mocker: Any, circuit_breaker: CircuitBreakerService, closed_circuit: Circuit
) -> None:
    url = closed_circuit.id
    func = mocker.AsyncMock(side_effect=Exception("Error"))

    for _ in range(3):
        with pytest.raises(Exception):
            await circuit_breaker.call(url, func)

    circuit = circuit_breaker.repository.get_circuit(url)
    assert circuit.state == CircuitState.OPEN
    assert circuit.fail_count == 3


@pytest.mark.asyncio
async def test_circuit_breaker_resets_after_success(
    mocker: Any, circuit_breaker: CircuitBreakerService, closed_circuit: Circuit
) -> None:
    url = closed_circuit.id
    failing_func = mocker.AsyncMock(side_effect=Exception("Error"))
    successful_func = mocker.AsyncMock(return_value="Success")

    # First two attempts fail
    for _ in range(2):
        with pytest.raises(Exception):
            await circuit_breaker.call(url, failing_func)

    # Third attempt succeeds, and the circuit should reset
    result = await circuit_breaker.call(url, successful_func)
    assert result == "Success"
    circuit = circuit_breaker.repository.get_circuit(url)
    assert circuit.state == CircuitState.CLOSED
    assert circuit.fail_count == 0


@pytest.mark.asyncio
async def test_circuit_breaker_open_state_can_attempt_reset(
    mocker: Any, circuit_breaker: CircuitBreakerService, open_circuit: Circuit
) -> None:
    url = open_circuit.id
    func = mocker.AsyncMock(return_value="Success")
    open_circuit.last_failure_time = (
        time.time() - 1
    )  # the fixture has a reset_timeout of 1 so it should be able to reset

    mocker.patch.object(circuit_breaker.repository, "save_circuit")
    result = await circuit_breaker.call(url, func)

    assert result == "Success"
    circuit = circuit_breaker.repository.get_circuit(url)
    assert circuit.state == CircuitState.CLOSED
    # Type is ignored here because the mock does, in fact, have a call_count attribute. as opposed to what the gaslighting mypy linter says
    assert circuit_breaker.repository.save_circuit.call_count == 1  # type: ignore


@pytest.mark.asyncio
async def test_circuit_breaker_open_state_cannot_attempt_reset(
    mocker: Any, circuit_breaker: CircuitBreakerService, open_circuit: Circuit
) -> None:
    url = open_circuit.id
    func = mocker.AsyncMock()
    open_circuit.last_failure_time = (
        time.time() - 0.5
    )  # the fixture has a reset_timeout of 1 so it should not be able to reset

    mocker.patch.object(circuit_breaker.repository, "save_circuit")

    with pytest.raises(CircuitOpenException):
        await circuit_breaker.call(url, func)

    circuit = circuit_breaker.repository.get_circuit(url)
    assert circuit.state == CircuitState.OPEN
    # Type is ignored here because the mock does, in fact, have a call_count attribute. as opposed to what the gaslighting mypy linter says
    assert circuit_breaker.repository.save_circuit.call_count == 0  # type: ignore


@pytest.mark.asyncio
async def test_circuit_breaker_raises_exception_on_open_circuit(
    mocker: Any, circuit_breaker: CircuitBreakerService, open_circuit: Circuit
) -> None:
    url = open_circuit.id
    open_circuit.last_failure_time = time.time()
    func = mocker.AsyncMock()

    with pytest.raises(CircuitOpenException):
        await circuit_breaker.call(url, func)

    assert func.call_count == 0
    assert open_circuit.state == CircuitState.OPEN
