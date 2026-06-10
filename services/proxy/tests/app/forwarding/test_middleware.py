from faker import Faker
from fastapi import HTTPException
from pytest import fixture, raises
from pytest_mock import MockerFixture, MockType

from app.config.models import ForwardingConfig
from app.forwarding.middleware import (
    validated_data_service_id_header,
    validated_healthcare_provider_id_header,
    validated_media_resource_url,
)
from app.medmij.exceptions import WhitelistError
from app.medmij.repositories import WhitelistRepository


class TestValidatedMediaResourceUrl:
    @fixture
    def mock_whitelist_repository(self, mocker: MockerFixture) -> MockType:
        mock_whitelist_repository: MockType = mocker.Mock(spec=WhitelistRepository)

        return mock_whitelist_repository

    def test_when_hostname_is_whitelisted_returns_url(
        self,
        mock_whitelist_repository: MockType,
        faker: Faker,
    ) -> None:
        hostname = faker.domain_name()
        media_resource_url = f"https://{hostname}/media/image.jpg"

        result = validated_media_resource_url(
            media_resource_url=media_resource_url,
            whitelist_repository=mock_whitelist_repository,
        )

        assert result == media_resource_url
        mock_whitelist_repository.assert_whitelisted.assert_called_once_with(hostname)

    def test_when_hostname_is_not_whitelisted_raises_whitelist_error(
        self,
        mock_whitelist_repository: MockType,
        faker: Faker,
    ) -> None:
        hostname = faker.domain_name()
        media_resource_url = f"https://{hostname}/media/image.jpg"

        mock_whitelist_repository.assert_whitelisted.side_effect = (
            WhitelistError.because_hostname_not_whitelisted(hostname)
        )

        with raises(WhitelistError, match=r"^Hostname is not whitelisted"):
            validated_media_resource_url(
                media_resource_url=media_resource_url,
                whitelist_repository=mock_whitelist_repository,
            )

    def test_when_url_parsing_fails_calls_assert_whitelisted_with_empty_string(
        self,
        mock_whitelist_repository: MockType,
        mocker: MockerFixture,
    ) -> None:
        mocker.patch(
            target="app.forwarding.middleware.urlparse",
            side_effect=Exception("Invalid URL"),
        )

        validated_media_resource_url(
            media_resource_url="not-a-url",
            whitelist_repository=mock_whitelist_repository,
        )

        mock_whitelist_repository.assert_whitelisted.assert_called_once_with("")


class TestValidatedHealthcareProviderIdHeader:
    def test_when_header_is_present_returns_value(self, faker: Faker) -> None:
        config = ForwardingConfig(require_provider_and_service_id=True)
        provider_id = faker.uuid4()

        result = validated_healthcare_provider_id_header(
            config=config,
            x_mgo_provider_id=provider_id,
        )

        assert result == provider_id

    def test_when_header_is_absent_and_not_required_returns_none(self) -> None:
        config = ForwardingConfig(require_provider_and_service_id=False)

        result = validated_healthcare_provider_id_header(
            config=config,
            x_mgo_provider_id=None,
        )

        assert result is None

    def test_when_header_is_absent_and_required_raises_http_422(self) -> None:
        config = ForwardingConfig(require_provider_and_service_id=True)

        with raises(HTTPException) as exc_info:
            validated_healthcare_provider_id_header(
                config=config,
                x_mgo_provider_id=None,
            )

        assert exc_info.value.status_code == 422


class TestValidatedDataServiceIdHeader:
    def test_when_header_is_present_returns_value(self, faker: Faker) -> None:
        config = ForwardingConfig(require_provider_and_service_id=True)
        service_id = faker.random_int(min=1)

        result = validated_data_service_id_header(
            config=config,
            x_mgo_service_id=service_id,
        )

        assert result == service_id

    def test_when_header_is_absent_and_not_required_returns_none(self) -> None:
        config = ForwardingConfig(require_provider_and_service_id=False)

        result = validated_data_service_id_header(
            config=config,
            x_mgo_service_id=None,
        )

        assert result is None

    def test_when_header_is_absent_and_required_raises_http_422(self) -> None:
        config = ForwardingConfig(require_provider_and_service_id=True)

        with raises(HTTPException) as exc_info:
            validated_data_service_id_header(
                config=config,
                x_mgo_service_id=None,
            )

        assert exc_info.value.status_code == 422
