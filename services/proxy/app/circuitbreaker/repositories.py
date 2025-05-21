import json
from abc import ABC, abstractmethod

import inject
from redis import Redis

from .models import Circuit


class CircuitStateRepository(ABC):
    TYPE_IN_MEMORY: str = "in_memory"
    TYPE_REDIS: str = "redis"

    @abstractmethod
    def get_circuit(self, identifier: str) -> Circuit:
        # these methods are not covered as they are abstract
        ...  # pragma: no cover

    @abstractmethod
    def save_circuit(self, circuit: Circuit) -> None:
        # these methods are not covered as they are abstract
        ...  # pragma: no cover


class InMemoryCircuitStateRepository(CircuitStateRepository):
    def __init__(self) -> None:
        self.storage: dict[str, Circuit] = {}

    def get_circuit(self, identifier: str) -> Circuit:
        return self.storage.get(identifier, Circuit(id=identifier))

    def save_circuit(self, circuit: Circuit) -> None:
        self.storage[circuit.id] = circuit


class RedisCircuitStateRepository(CircuitStateRepository):
    redis: Redis

    @inject.autoparams()
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    def get_circuit(self, identifier: str) -> Circuit:
        circuit = self.redis.get(identifier)

        # Type checking requires us to assert that circuit is in string representation here
        if circuit and isinstance(circuit, str):
            return Circuit(**json.loads(circuit))

        return Circuit(id=identifier)

    def save_circuit(self, circuit: Circuit) -> None:
        try:
            self.redis.set(circuit.id, circuit.model_dump_json())
        except Exception as e:
            raise Exception(f"Error saving circuit {circuit.id}: {e}")
