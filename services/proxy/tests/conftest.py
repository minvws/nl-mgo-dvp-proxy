from base64 import urlsafe_b64encode
from collections.abc import Callable
from typing import Generator

import inject
import pytest
from faker import Faker
from fastapi.testclient import TestClient
from jwcrypto.jwk import JWK

from app.config.models import DvaTargetConfig
from app.forwarding.schemas import ForwardMediaResourceRequestHeaders
from app.main import create_app
from tests.app.test_utils import create_jwe
from tests.utils import clear_bindings, configure_bindings


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture()
def test_client() -> Generator[TestClient, None, None]:
    configure_bindings()
    yield TestClient(create_app())
    clear_bindings()


@pytest.fixture()
def faker() -> Faker:
    return Faker()


@pytest.fixture
def mock_dva_endpoint_jwe(faker: Faker) -> str:
    length = faker.random_element([12, 16, 32, 64])
    return ".".join(
        urlsafe_b64encode(faker.binary(length=length)).decode("utf-8").rstrip("=")
        for _ in range(5)
    )


@pytest.fixture
def dva_endpoint_jwe(faker: Faker) -> str:
    dva_target_config = inject.instance(DvaTargetConfig)
    jwt_signing_private_key_path = dva_target_config.jwt_signing_public_key.replace(
        ".pub", ".key"
    )
    jwe_encryption_public_key_path = (
        dva_target_config.jwe_encryption_private_key.replace(".key", ".pub")
    )

    with open(jwt_signing_private_key_path, "rb") as f:
        jwt_signing_private_key = JWK.from_pem(f.read())

    with open(jwe_encryption_public_key_path, "rb") as f:
        jwe_encryption_public_key = JWK.from_pem(f.read())

    return create_jwe(
        jwe_encryption_public_key=jwe_encryption_public_key,
        jwt_signing_private_key=jwt_signing_private_key,
        url=faker.url(),
        iat=0,
        exp=2147483647,
    )


@pytest.fixture
def make_forward_media_resource_request_headers(
    faker: Faker,
) -> Callable[..., ForwardMediaResourceRequestHeaders]:
    def factory(
        access_token: str | None = None,
        correlation_id: str | None = None,
    ) -> ForwardMediaResourceRequestHeaders:
        return ForwardMediaResourceRequestHeaders(
            media_resource_url=faker.url(),
            access_token=access_token,
            correlation_id=correlation_id,
            healthcare_provider_id=None,
            data_service_id=None,
        )

    return factory
