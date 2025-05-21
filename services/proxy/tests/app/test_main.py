import os

import inject
import pytest
from pytest_mock import MockerFixture

from app.config.services import ConfigParser
from app.main import create_app
from app.utils import root_path
from tests.utils import clear_bindings, configure_bindings


def teardown_function() -> None:
    clear_bindings()


def test_create_app_parses_app_config(mocker: MockerFixture) -> None:
    config_path = root_path("app.conf")
    if not os.path.isfile(config_path):
        pytest.fail(f"This test requires config file {config_path} to exist")

    inject_configure_spy = mocker.spy(inject, "configure")
    config_parser_init_spy = mocker.spy(ConfigParser, "__init__")
    create_app()
    inject_configure_spy.assert_called()
    config_parser_init_spy.assert_called_once_with(
        mocker.ANY,
        mocker.ANY,
        root_path("app.conf"),
    )


def test_create_app_does_not_reconfigure_inject(mocker: MockerFixture) -> None:
    configure_bindings()
    inject_configure_spy = mocker.spy(inject, "configure")
    create_app()
    inject_configure_spy.assert_not_called()
