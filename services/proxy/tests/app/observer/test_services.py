from pytest_mock import MockerFixture

from app.observer.services import EventListener, EventManager


class EventA:
    pass


class EventB:
    pass


class ListenerA:
    def handle(self, event: object) -> None:
        _ = event


class ListenerB:
    def handle(self, event: object) -> None:
        _ = event


class TestEventManager:
    def test_subscribe_registers_listener_for_event_type(self) -> None:
        sut = EventManager()
        listener_a = ListenerA()
        listener_b = ListenerB()

        sut.subscribe(EventA, listener_a)
        sut.subscribe(EventA, listener_b)
        sut.subscribe(EventB, listener_a)

        assert sut._listeners[EventA] == [listener_a, listener_b]
        assert sut._listeners[EventB] == [listener_a]

    def test_notify_dispatches_event_to_all_registered_listeners(
        self,
        mocker: MockerFixture,
    ) -> None:
        sut = EventManager()
        event = EventA()
        listener_a = mocker.Mock(spec=EventListener)
        listener_b = mocker.Mock(spec=EventListener)

        sut.subscribe(EventA, listener_a)
        sut.subscribe(EventA, listener_b)

        sut.notify(event)

        listener_a.handle.assert_called_once_with(event)
        listener_b.handle.assert_called_once_with(event)

    def test_notify_does_not_dispatch_to_listeners_of_other_event_types(
        self,
        mocker: MockerFixture,
    ) -> None:
        sut = EventManager()
        listener = mocker.Mock(spec=EventListener)

        sut.subscribe(EventA, listener)

        sut.notify(EventB())

        listener.handle.assert_not_called()
