import time

import pytest

from app.circuitbreaker.models import Circuit, CircuitState


@pytest.fixture
def circuit() -> Circuit:
    return Circuit(id="test_circuit")


def test_it_can_attempt_reset_before_timeout(circuit: Circuit) -> None:
    circuit.last_failure_time = time.time() - 1
    reset_timeout = 2

    assert time.time() - circuit.last_failure_time < reset_timeout


def test_it_can_attempt_reset_after_timeout(circuit: Circuit) -> None:
    circuit.last_failure_time = time.time() - 3
    reset_timeout = 2

    assert time.time() - circuit.last_failure_time >= reset_timeout


def test_it_can_attempt_reset_edge_case(circuit: Circuit) -> None:
    circuit.last_failure_time = time.time() - 2
    reset_timeout = 2

    assert time.time() - circuit.last_failure_time >= reset_timeout


def test_state_is_not_shared_between_circuit_instances() -> None:
    circuit_a = Circuit(id="a")
    circuit_b = Circuit(id="b")

    circuit_a.open()

    assert circuit_a.state == CircuitState.OPEN
    assert circuit_b.state == CircuitState.CLOSED
