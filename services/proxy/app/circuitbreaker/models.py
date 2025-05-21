import time
from enum import Enum

from pydantic import BaseModel, Field


class CircuitState(Enum):
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"
    CLOSED = "CLOSED"


class Circuit(BaseModel):
    id: str
    state: CircuitState = Field(default=CircuitState.CLOSED)
    fail_count: int = Field(default=0)
    last_failure_time: float = Field(default=0.0)

    def reset(self) -> None:
        self.state = CircuitState.CLOSED
        self.fail_count = 0
        self.last_failure_time = 0.0

    def record_failure(self) -> None:
        self.fail_count += 1
        self.last_failure_time = time.time()

    def open(self) -> None:
        self.state = CircuitState.OPEN
        self.last_failure_time = time.time()


class CircuitOpenException(Exception):
    pass
