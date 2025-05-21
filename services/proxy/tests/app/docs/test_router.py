from fastapi.testclient import TestClient


def test_it_can_request_the_docs_url(
    test_client: TestClient,
) -> None:
    response = test_client.get("/docs")
    assert response.status_code == 200
    assert "Swagger UI" in response.text


def test_it_can_request_the_swagger_ui_assets(
    test_client: TestClient,
) -> None:
    response = test_client.get("/static/swagger-ui-bundle.js")
    assert response.status_code == 200
    assert (
        "/*! For license information please see swagger-ui-bundle.js.LICENSE.txt */"
        in response.text
    )
