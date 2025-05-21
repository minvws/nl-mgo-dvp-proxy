import logging

import inject
from pytest import CaptureFixture

from tests.utils import clear_bindings, configure_bindings, load_app_config


def test_logger_binding_resolves_the_main_application_logger() -> None:
    configure_bindings()

    app_config = load_app_config()

    expected_logger: logging.Logger = logging.getLogger(app_config.logging.logger_name)
    resolved_logger: logging.Logger = inject.instance(logging.Logger)

    assert resolved_logger == expected_logger

    clear_bindings()


def test_logger_writes_output_to_console(capfd: CaptureFixture[str]) -> None:
    configure_bindings()

    test_message = "This is a test log message."

    logger: logging.Logger = inject.instance(logging.Logger)
    logger.debug(test_message)

    assert test_message in capfd.readouterr().out

    clear_bindings()
