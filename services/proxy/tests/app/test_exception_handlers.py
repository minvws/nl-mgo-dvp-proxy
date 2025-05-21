import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pytest_mock import MockerFixture

from app.exception_handlers import ExceptionHandlers
from tests.utils import clear_bindings, configure_bindings


class TestExceptionHandlers:
    @pytest.mark.anyio
    async def test_general_exception_handler(self, mocker: MockerFixture) -> None:
        configure_bindings()

        app = FastAPI()
        ExceptionHandlers.load_handlers(app)

        @app.get("/raise-exception")
        async def raise_exception() -> None:
            raise Exception("exception")

        client = TestClient(app=app, raise_server_exceptions=False)
        response = client.get("/raise-exception")

        assert response.status_code == 500
        assert response.json() == {"detail": "Internal Server Error"}

        clear_bindings()
