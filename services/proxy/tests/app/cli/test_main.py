import runpy

from pytest_mock import MockerFixture

from app.cli.main import bootstrap


def test_bootstrap_when_inject_not_configured_configures_bindings(
    mocker: MockerFixture,
) -> None:
    mock_is_configured = mocker.patch("inject.is_configured", return_value=False)
    mock_configure = mocker.patch("inject.configure")

    bootstrap()

    mock_is_configured.assert_called_once_with()
    mock_configure.assert_called_once_with(mocker.ANY)


def test_bootstrap_when_inject_is_configured_does_not_configure_again(
    mocker: MockerFixture,
) -> None:
    mock_is_configured = mocker.patch("inject.is_configured", return_value=True)
    mock_configure = mocker.patch("inject.configure")

    bootstrap()

    mock_is_configured.assert_called_once_with()
    mock_configure.assert_not_called()


def test_main_when_run_as_script_invokes_cli_app(
    mocker: MockerFixture,
) -> None:
    mock_typer_call = mocker.patch("typer.main.Typer.__call__", return_value=None)

    runpy.run_module("app.cli.main", run_name="__main__")

    mock_typer_call.assert_called_once_with()
