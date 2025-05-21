import inject
import pytest

from app.config.models import AppConfig, Environment


@pytest.mark.usefixtures("test_client")
def test_test_client_fixture_loads_testing_configuration_by_default() -> None:
    app_config: AppConfig = inject.instance(AppConfig)
    assert app_config.env == Environment.TESTING
