from faker import Faker
from fastapi.testclient import TestClient

from app.version.models import VersionInfo
from tests.utils import configure_bindings


def test_root_endpoint_prints_version_info(
    test_client: TestClient, faker: Faker
) -> None:
    version = faker.numerify("v#.#.#")
    git_ref = faker.hexify("^^^^^^")

    configure_bindings(
        lambda binder: binder.bind(
            VersionInfo,
            VersionInfo(version=version, git_ref=git_ref),
        ),
    )

    response = test_client.get("/")

    assert response.status_code == 200
    assert response.text == f'{{"version":"{version}","git_ref":"{git_ref}"}}'
