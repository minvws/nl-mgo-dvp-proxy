from pytest_mock import MockerFixture

from app.config.models import TelemetryConfig
from app.main import create_app
from app.telemetry.jaeger_provider import setup_jaeger


def test_it_calls_instrument_app_when_enabled(mocker: MockerFixture) -> None:
    config = TelemetryConfig(
        enabled=True, service_name="test", collector_grpc_url="http://localhost:4317"
    )

    patched_instrument_app = mocker.patch(
        "app.telemetry.jaeger_provider.FastAPIInstrumentor.instrument_app"
    )
    setup_jaeger(create_app(), config)

    patched_instrument_app.assert_called_once()


def test_it_does_not_call_instrument_app_when_disabled(mocker: MockerFixture) -> None:
    config = TelemetryConfig(
        enabled=False, service_name="test", collector_grpc_url="http://localhost:4317"
    )

    patched_instrument_app = mocker.patch(
        "app.telemetry.jaeger_provider.FastAPIInstrumentor.instrument_app"
    )
    setup_jaeger(create_app(), config)

    patched_instrument_app.assert_not_called()
