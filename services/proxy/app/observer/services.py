from collections import defaultdict
from typing import Protocol, TypeVar, cast

EventType = TypeVar("EventType")
EventTypeContra = TypeVar("EventTypeContra", contravariant=True)


class EventListener(Protocol[EventTypeContra]):
    def handle(self, event: EventTypeContra) -> None: ...


class EventManager:
    def __init__(self) -> None:
        self._listeners: dict[type, list[EventListener[object]]] = defaultdict(list)

    def subscribe(
        self, event: type[EventType], listener: EventListener[EventType]
    ) -> None:
        self._listeners[event].append(cast(EventListener[object], listener))

    def notify(self, event: EventType) -> None:
        for listener in self._listeners.get(type(event), []):
            cast(EventListener[EventType], listener).handle(event)
