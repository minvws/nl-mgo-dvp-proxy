import time
from logging import Logger
from typing import Any, Callable, Coroutine

import inject

from .models import CircuitOpenException, CircuitState
from .repositories import CircuitStateRepository


class CircuitBreakerService:
    @inject.autoparams("logger")
    def __init__(
        self,
        repository: CircuitStateRepository,
        logger: Logger,
        fail_max: int = 3,
        reset_timeout: int = 60,
    ) -> None:
        self.repository = repository
        self.logger = logger
        self.fail_max = fail_max
        self.reset_timeout = reset_timeout

    async def call(
        self,
        identifier: str,
        func: Callable[..., Coroutine[Any, Any, Any]],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        self.logger.debug(
            f"retrieving circuit from %s: %s", self.repository, identifier
        )
        circuit = self.repository.get_circuit(identifier)

        if circuit.state == CircuitState.OPEN:
            if time.time() - circuit.last_failure_time >= self.reset_timeout:
                circuit.state = CircuitState.HALF_OPEN
            else:
                self.logger.info(
                    f"Circuit for %s is open. Function call not attempted.", identifier
                )
                raise CircuitOpenException(
                    f"Circuit for %s opened due to consecutive failures.", identifier
                )

        try:
            result = await func(*args, **kwargs)
            circuit.reset()
            self.repository.save_circuit(circuit)

            return result
        except Exception as e:
            circuit.record_failure()

            if circuit.fail_count >= self.fail_max:
                circuit.open()
                self.logger.warning(
                    f"Circuit for {identifier} opened due to consecutive failures.",
                    e,
                )

            self.repository.save_circuit(circuit)
            raise e
