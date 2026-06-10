import configparser
from pathlib import Path

import pytest

from app.config.models import AppConfig
from app.config.services import ConfigParser
from app.utils import root_path


class TestConfigParser:
    def test_config_file_is_valid_to_parse(self) -> None:
        config_parser = ConfigParser(
            config_parser=configparser.ConfigParser(),
            config_path=root_path("app.conf.test"),
        )
        app_config = config_parser.parse()

        assert isinstance(app_config, AppConfig)
        assert app_config.medmij_whitelist.pull_max_retries == 10
        assert app_config.medmij_whitelist.pull_initial_backoff_secs == 0.5
        assert app_config.medmij_whitelist.pull_backoff_factor == 2.0

    def test_parse_config_with_missing_file(self, tmp_path: Path) -> None:
        missing_conf = tmp_path / "missing.conf"
        config_parser = ConfigParser(
            config_parser=configparser.ConfigParser(),
            config_path=str(missing_conf),
        )

        with pytest.raises(FileNotFoundError):
            config_parser.parse()
