from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from httpx import Response

from app.config.models import AppConfig
from tests.utils import clear_bindings, configure_bindings, load_app_config


class TestOAuthFlow:
    def test_handle_oauth_flow_success(
        self,
        test_client: TestClient,
    ) -> None:
        # Even though we do not normally mock in feature tests, the signature part is very hard to simulate as the keys are generated elsewhere
        # Hence, we turn off the signature validation, and test that we exit with a 403 when signature validation is turned on
        config = load_app_config()
        config.signature_validation.verify_signed_requests = False
        configure_bindings(lambda binder: binder.bind(AppConfig, config))

        response = test_client.post(
            f"/getstate",
            json={
                "authorization_server_url": "https://authorization-server.com/authorize",
                "token_endpoint_url": "https://authorization-server.com/auth/token",
                "medmij_scope": "eenofanderezorgaanbieder",
                "client_target_url": "https://client.example.com/callback",
            },
            follow_redirects=False,
        )

        assert response.status_code == 200
        content = response.json()

        parsed_url = urlparse(content["url_to_request"])
        query_params = parse_qs(parsed_url.query)
        proxy_callback_url = "/auth/callback"
        params: dict[str, str] = {
            "state": query_params["state"][0],
            "code": "dummy_access_token",
        }

        callback_response: Response = test_client.get(
            proxy_callback_url, params=params, follow_redirects=False
        )

        parsed_client_target_url = urlparse(callback_response.headers["location"])
        client_target_query_params = parse_qs(parsed_client_target_url.query)

        # Create a normalized URL object
        url_object = {
            "scheme": parsed_client_target_url.scheme,
            "netloc": parsed_client_target_url.netloc,
            "path": parsed_client_target_url.path,
            "params": parsed_client_target_url.params,
            "query": client_target_query_params,
            "fragment": parsed_client_target_url.fragment,
        }

        assert url_object["netloc"] == "client.example.com"
        assert url_object["path"] == "/callback"
        assert client_target_query_params["access_code"][0] == "mocked_access_token"
        assert client_target_query_params["token_type"][0] == "Bearer"
        assert client_target_query_params["expires_in"][0] == "900"
        assert client_target_query_params["refresh_code"][0] == "mocked_refresh_token"
        assert client_target_query_params["scope"][0] == "48 49"
        clear_bindings()

    def test_flow_is_not_executed_when_signature_is_missing(
        self, test_client: TestClient
    ) -> None:
        response = test_client.post(
            f"/getstate",
            json={
                "authorization_server_url": "https://authorization-server.com/auth/authorize",
                "token_endpoint_url": "https://authorization-server.com/auth/token",
                "medmij_scope": "eenofanderezorgaanbieder",
                "client_target_url": "https://client.example.com/callback",
            },
            follow_redirects=False,
        )

        assert response.status_code == 403
