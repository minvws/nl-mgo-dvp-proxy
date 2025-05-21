import os

import pytest

from app.utils import root_path


@pytest.mark.parametrize(
    "args, expected_relative_path",
    [
        (["data", "file.txt"], "data/file.txt"),
        (["config", "settings"], "config/settings"),
        ([], ""),
    ],
)
def test_root_path(args: list[str], expected_relative_path: str) -> None:
    test_dir = os.path.abspath(os.path.dirname(__file__))
    result = root_path(*args)
    expected_absolute_path = os.path.abspath(
        os.path.join(
            test_dir,
            "..",
            "..",
            expected_relative_path,
        ),
    )
    assert result == expected_absolute_path
