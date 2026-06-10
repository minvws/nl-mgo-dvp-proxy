import logging
from typing import Callable, Tuple

import inject
from inject import Binder
from pytest import LogCaptureFixture

from app.bindings import configure_bindings as configure_app_bindings
from app.config.models import AppConfig


def configure_bindings(
    bindings_override: Callable[[Binder], Binder] | None = None,
) -> None:
    """
    Configures dependency injection bindings for the application.

    Sets up standard bindings using `app.conf.test`.
    If `bindings_override` is provided, it overrides bindings over other bindings.
    """

    def bindings_config(binder: inject.Binder) -> None:
        binder.install(
            lambda binder: configure_app_bindings(binder, config_file="app.conf.test")
        )

        if bindings_override:
            bindings_override(binder)

    inject.configure(bindings_config, clear=True, allow_override=True)


def clear_bindings() -> None:
    inject.clear()


def load_app_config() -> AppConfig:
    if not inject.is_configured():
        configure_bindings()

    app_config: AppConfig = inject.instance(AppConfig)
    return app_config


def assert_captured_logs(
    caplog: LogCaptureFixture, expected: list[Tuple[str, int]]
) -> None:
    """
    Helper to assert that each expected message appears in logs with correct severity.

    Usage:
        def test_example(caplog: LogCaptureFixture):
            expected_logs = [
                ("Process completed successfully", logging.INFO),
                ("Warning: something minor happened", logging.WARNING),
            ]
            assert_captured_logs(caplog, expected_logs)
    """
    for msg, level in expected:
        assert any(
            msg in record.message and record.levelno == level
            for record in caplog.records
        ), f"Expected log '{msg}' with level {logging.getLevelName(level)}"
