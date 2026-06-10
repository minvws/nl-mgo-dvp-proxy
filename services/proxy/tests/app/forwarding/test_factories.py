import uuid
from collections.abc import Callable

from faker import Faker
from pytest import fixture
from pytest_mock import MockerFixture, MockType

from app.forwarding.constants import (
    MEDMIJ_CORRELATION_ID_HEADER,
    MEDMIJ_REQUEST_ID_HEADER,
)
from app.forwarding.factories import (
    MediaResourceGatewayHeaderFactory,
    MinimalMediaResourceGatewayHeaderFactory,
    OpenTelemetryMediaResourceGatewayHeaderFactory,
)
from app.forwarding.schemas import ForwardMediaResourceRequestHeaders


class TestMinimalMediaResourceGatewayHeaderFactory:
    def test_create_always_includes_request_id(
        self,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
    ) -> None:
        sut = MinimalMediaResourceGatewayHeaderFactory()

        result = sut.create(make_forward_media_resource_request_headers())

        request_id = result[MEDMIJ_REQUEST_ID_HEADER]
        assert uuid.UUID(request_id)

    def test_create_includes_authorization_header_when_access_token_is_present(
        self,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
        faker: Faker,
    ) -> None:
        token = faker.sha256()
        sut = MinimalMediaResourceGatewayHeaderFactory()

        result = sut.create(
            make_forward_media_resource_request_headers(access_token=token)
        )

        assert result["Authorization"] == f"Bearer {token}"

    def test_create_omits_authorization_header_when_access_token_is_absent(
        self,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
    ) -> None:
        sut = MinimalMediaResourceGatewayHeaderFactory()

        result = sut.create(
            make_forward_media_resource_request_headers(access_token=None)
        )

        assert "Authorization" not in result

    def test_create_includes_correlation_id_header_when_present(
        self,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
        faker: Faker,
    ) -> None:
        correlation_id = str(faker.uuid4())
        sut = MinimalMediaResourceGatewayHeaderFactory()

        result = sut.create(
            make_forward_media_resource_request_headers(correlation_id=correlation_id)
        )

        assert result[MEDMIJ_CORRELATION_ID_HEADER] == correlation_id

    def test_create_omits_correlation_id_header_when_absent(
        self,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
    ) -> None:
        sut = MinimalMediaResourceGatewayHeaderFactory()

        result = sut.create(
            make_forward_media_resource_request_headers(correlation_id=None)
        )

        assert MEDMIJ_CORRELATION_ID_HEADER not in result

    def test_create_generates_unique_request_id_on_each_call(
        self,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
    ) -> None:
        sut = MinimalMediaResourceGatewayHeaderFactory()
        request_headers = make_forward_media_resource_request_headers()

        first = sut.create(request_headers)[MEDMIJ_REQUEST_ID_HEADER]
        second = sut.create(request_headers)[MEDMIJ_REQUEST_ID_HEADER]

        assert first != second


class TestOpenTelemetryMediaResourceGatewayHeaderFactory:
    @fixture
    def mock_decorated(self, mocker: MockerFixture) -> MockType:
        mock_factory: MockType = mocker.Mock(spec=MediaResourceGatewayHeaderFactory)

        return mock_factory

    def test_create_returns_headers_from_decorated_factory(
        self,
        mock_decorated: MockType,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
        faker: Faker,
    ) -> None:
        base_headers = {MEDMIJ_REQUEST_ID_HEADER: str(faker.uuid4())}
        request_headers = make_forward_media_resource_request_headers()
        sut = OpenTelemetryMediaResourceGatewayHeaderFactory(decorated=mock_decorated)

        mock_decorated.create.return_value = base_headers

        result = sut.create(request_headers)

        assert MEDMIJ_REQUEST_ID_HEADER in result

        mock_decorated.create.assert_called_once_with(request_headers)

    def test_create_injects_trace_context_into_headers(
        self,
        mock_decorated: MockType,
        make_forward_media_resource_request_headers: Callable[
            ..., ForwardMediaResourceRequestHeaders
        ],
        mocker: MockerFixture,
    ) -> None:
        sut = OpenTelemetryMediaResourceGatewayHeaderFactory(decorated=mock_decorated)

        propagate_inject = mocker.patch("app.forwarding.factories.propagate.inject")
        mock_decorated.create.return_value = {}

        sut.create(make_forward_media_resource_request_headers())

        propagate_inject.assert_called_once()
