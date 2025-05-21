from typing import Generator

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.utils import clear_bindings, configure_bindings


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture()
def test_client() -> Generator[TestClient, None, None]:
    configure_bindings()
    yield TestClient(create_app())
    clear_bindings()
