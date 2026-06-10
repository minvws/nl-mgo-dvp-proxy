import pytest
from pytest_mock import MockerFixture
from typer.testing import CliRunner

from app.medmij.commands import medmij_app as medmij_cli_app
from app.medmij.services import MedMijWhitelistPuller
from tests.utils import configure_bindings

runner = CliRunner()


@pytest.mark.usefixtures("test_client")
def test_pull_whitelist_bootstraps_with_default_app_config(
    mocker: MockerFixture,
) -> None:
    whitelist_puller = mocker.Mock(spec=MedMijWhitelistPuller)
    whitelist_puller.pull_and_refresh.return_value = 2

    configure_bindings(
        bindings_override=lambda binder: binder.bind(
            MedMijWhitelistPuller, whitelist_puller
        )
    )

    result = runner.invoke(medmij_cli_app, [])

    assert result.exit_code == 0
    whitelist_puller.pull_and_refresh.assert_called_once_with()


@pytest.mark.usefixtures("test_client")
def test_pull_whitelist_returns_exit_code_1_on_failure(
    mocker: MockerFixture,
) -> None:
    whitelist_puller = mocker.Mock(spec=MedMijWhitelistPuller)
    whitelist_puller.pull_and_refresh.side_effect = Exception("boom")
    configure_bindings(
        bindings_override=lambda binder: binder.bind(
            MedMijWhitelistPuller, whitelist_puller
        )
    )

    result = runner.invoke(medmij_cli_app, [])

    assert result.exit_code == 1
    assert "Failed to pull MedMij whitelist: boom" in result.output
    whitelist_puller.pull_and_refresh.assert_called_once_with()
