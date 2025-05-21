from base64 import urlsafe_b64encode

from faker import Faker
from fastapi.testclient import TestClient
from pytest_mock import MockerFixture

from app.oidc.schemas import State, VadUserinfoResponse
from app.oidc.services import (
    ClientCallbackUrlDecorator,
    VadAuthorizationUrlProvider,
    VadUserinfoProvider,
)
from app.security.services import Encrypter
from tests.utils import configure_bindings


class TestVadRouter:
    def test_oidc_start_returns_authz_url(
        self,
        mocker: MockerFixture,
        faker: Faker,
        test_client: TestClient,
    ) -> None:
        client_callback_url = faker.url()
        authz_url = faker.url()
        mock_authz_url_provider = mocker.Mock(spec=VadAuthorizationUrlProvider)
        configure_bindings(
            lambda binder: binder.bind(
                VadAuthorizationUrlProvider, mock_authz_url_provider
            )
        )

        mock_authz_url_provider.invoke.return_value = authz_url

        response = test_client.post(
            "/oidc/start",
            json={
                "client_callback_url": client_callback_url,
            },
        )

        assert response.status_code == 200
        assert response.json() == {"authz_url": authz_url}

        mock_authz_url_provider.invoke.assert_called_once_with(client_callback_url)

    def test_oidc_start_options_request(self, test_client: TestClient) -> None:
        response = test_client.options(
            "/oidc/start",
            headers={
                "Origin": "http://localhost:8000",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "*"
        assert "POST" in response.headers["access-control-allow-methods"]

    def test_oidc_start_errors_when_client_callback_url_not_provided(
        self,
        mocker: MockerFixture,
        test_client: TestClient,
    ) -> None:
        mock_authz_url_provider = mocker.Mock(spec=VadAuthorizationUrlProvider)
        configure_bindings(
            lambda binder: binder.bind(
                VadAuthorizationUrlProvider, mock_authz_url_provider
            )
        )

        response = test_client.post("/oidc/start", json={})

        assert response.status_code == 422
        assert response.json() == {
            "detail": [
                {
                    "type": "missing",
                    "loc": ["body", "client_callback_url"],
                    "msg": "Field required",
                    "input": {},
                }
            ]
        }

    def test_oidc_callback_redirects_to_client_userinfo_url(
        self,
        mocker: MockerFixture,
        faker: Faker,
        test_client: TestClient,
    ) -> None:
        mock_userinfo_provider = mocker.Mock(spec=VadUserinfoProvider)
        mock_encrypter = mocker.Mock(spec=Encrypter)
        mock_client_callback_url_decorator = mocker.Mock(
            spec=ClientCallbackUrlDecorator
        )
        configure_bindings(
            lambda binder: binder.bind(VadUserinfoProvider, mock_userinfo_provider)
            .bind(Encrypter, mock_encrypter)
            .bind(ClientCallbackUrlDecorator, mock_client_callback_url_decorator)
        )

        code = faker.word()
        encrypted_state = str(faker.sha256(raw_output=True))
        state = State(
            client_callback_url=faker.url(),
            code_verifier=urlsafe_b64encode(faker.binary(32)).decode(),
        )
        vad_userinfo_response = VadUserinfoResponse(
            rid=str(faker.sha256(raw_output=True)),
            person={
                "age": faker.random_int(min=18, max=99),
                "name": {
                    "first_name": faker.first_name(),
                    "last_name": faker.last_name(),
                },
            },
            sub=faker.pystr(),
        )
        client_userinfo_url = faker.url()

        mock_encrypter.decrypt.return_value = state.model_dump_json()
        mock_userinfo_provider.invoke.return_value = vad_userinfo_response
        mock_client_callback_url_decorator.decorate_with_userinfo_data.return_value = (
            client_userinfo_url
        )

        response = test_client.get(
            "/oidc/callback",
            params={
                "code": code,
                "state": encrypted_state,
            },
            follow_redirects=False,
        )

        assert response.status_code == 302
        assert response.headers["location"] == client_userinfo_url

        mock_encrypter.decrypt.assert_called_once_with(encrypted_state)
        mock_userinfo_provider.invoke.assert_called_once_with(code, state)
        mock_client_callback_url_decorator.decorate_with_userinfo_data.assert_called_once_with(
            vad_userinfo_response, state
        )

    def test_oidc_callback_errors_when_code_not_provided(
        self,
        mocker: MockerFixture,
        faker: Faker,
        test_client: TestClient,
    ) -> None:
        mock_userinfo_provider = mocker.Mock(spec=VadUserinfoProvider)
        mock_encrypter = mocker.Mock(spec=Encrypter)
        mock_client_callback_url_decorator = mocker.Mock(
            spec=ClientCallbackUrlDecorator
        )
        configure_bindings(
            lambda binder: binder.bind(VadUserinfoProvider, mock_userinfo_provider)
            .bind(Encrypter, mock_encrypter)
            .bind(ClientCallbackUrlDecorator, mock_client_callback_url_decorator)
        )

        response = test_client.get(
            "/oidc/callback",
            params={
                "state": str(faker.sha256(raw_output=True)),
            },
            follow_redirects=False,
        )

        assert response.status_code == 422
        assert response.json() == {
            "detail": [
                {
                    "type": "missing",
                    "loc": ["query", "code"],
                    "msg": "Field required",
                    "input": None,
                }
            ]
        }

    def test_oidc_callback_errors_when_state_not_provided(
        self,
        mocker: MockerFixture,
        faker: Faker,
        test_client: TestClient,
    ) -> None:
        mock_userinfo_provider = mocker.Mock(spec=VadUserinfoProvider)
        mock_encrypter = mocker.Mock(spec=Encrypter)
        mock_client_callback_url_decorator = mocker.Mock(
            spec=ClientCallbackUrlDecorator
        )
        configure_bindings(
            lambda binder: binder.bind(VadUserinfoProvider, mock_userinfo_provider)
            .bind(Encrypter, mock_encrypter)
            .bind(ClientCallbackUrlDecorator, mock_client_callback_url_decorator)
        )

        response = test_client.get(
            "/oidc/callback",
            params={
                "code": faker.word(),
            },
            follow_redirects=False,
        )

        assert response.status_code == 422
        assert response.json() == {
            "detail": [
                {
                    "type": "missing",
                    "loc": ["query", "state"],
                    "msg": "Field required",
                    "input": None,
                }
            ]
        }
