import json
from pathlib import Path

import pytest
import xmlschema
from faker import Faker
from pytest_mock import MockerFixture
from redis import Redis

from app.medmij.exceptions import WhitelistError
from app.medmij.repositories import (
    FilesystemWhitelistXsdRepository,
    InMemoryWhitelistRepository,
    RedisWhitelistRepository,
)
from app.medmij.services import MedMijWhitelistPuller
from app.utils import root_path


class TestFilesystemWhitelistXsdRepository:
    def test_get_schema_from_cache_when_cache_is_injected_uses_injected_cache(
        self,
        mocker: MockerFixture,
    ) -> None:
        schema = mocker.Mock(spec=xmlschema.XMLSchemaBase)
        repo = FilesystemWhitelistXsdRepository(xsd_cache={"whitelist": schema})

        assert repo.get_schema_from_cache("whitelist") is schema

    def test_get_schema_from_cache_when_schema_is_registered_returns_schema(
        self,
        mocker: MockerFixture,
    ) -> None:
        fake_namespace = Faker().uri()
        schema = mocker.Mock(spec=xmlschema.XMLSchemaBase)
        schema.target_namespace = fake_namespace

        pre_made_cache = {MedMijWhitelistPuller.WHITELIST_XSD_LABEL: schema}

        repo = FilesystemWhitelistXsdRepository(pre_made_cache)
        schema = repo.get_schema_from_cache(MedMijWhitelistPuller.WHITELIST_XSD_LABEL)

        assert isinstance(schema, xmlschema.XMLSchemaBase)
        assert schema.target_namespace == fake_namespace

    def test_add_schema_to_cache_when_xsd_path_does_not_exist_raises_value_error(
        self,
    ) -> None:
        repo = FilesystemWhitelistXsdRepository()

        with pytest.raises(ValueError, match="file not found"):
            repo.add_schema_to_cache(
                xsd_label="unknown",
                xsd_path=root_path("resources", "medmij", "does_not_exist.xsd"),
            )

    def test_add_schema_to_cache_when_xsd_content_is_invalid_raises_value_error(
        self,
        tmp_path: Path,
    ) -> None:
        repo = FilesystemWhitelistXsdRepository()
        invalid_xsd_file = tmp_path / "invalid.xsd"
        invalid_xsd_file.write_text("this is not xsd", encoding="utf-8")

        with pytest.raises(ValueError, match="invalid XSD"):
            repo.add_schema_to_cache(
                xsd_label="invalid",
                xsd_path=str(invalid_xsd_file),
            )

    def test_get_schema_from_cache_when_label_is_missing_raises_key_error(self) -> None:
        repo = FilesystemWhitelistXsdRepository()

        with pytest.raises(KeyError, match="not available in cache"):
            repo.get_schema_from_cache("missing")


class TestRedisWhitelistRepository:
    def test_refresh_cache_when_data_is_valid_updates_redis_atomically(
        self,
        mocker: MockerFixture,
    ) -> None:
        redis = mocker.Mock(spec=Redis)
        pipeline = mocker.Mock()
        redis.pipeline.return_value = pipeline

        repo = RedisWhitelistRepository(redis=redis)
        hostnames = ["zanode.zorginstelling.nl", "mijn.zorginstelling.nl"]
        synced_at = "2026-04-02T09:30:00"

        repo.refresh_cache(hostnames=hostnames, synced_at=synced_at)

        redis.pipeline.assert_called_once_with(transaction=True)
        assert pipeline.set.call_count == 2
        assert pipeline.rename.call_count == 2
        pipeline.execute.assert_called_once()

        serialized_hostnames = pipeline.set.call_args_list[0][0][1]
        assert json.loads(serialized_hostnames) == hostnames

    def test_refresh_cache_when_redis_is_unavailable_raises_runtime_error(
        self,
        mocker: MockerFixture,
    ) -> None:
        redis = mocker.Mock(spec=Redis)
        redis.pipeline.side_effect = RuntimeError("redis unavailable")

        repo = RedisWhitelistRepository(redis=redis)

        with pytest.raises(RuntimeError, match="redis unavailable"):
            repo.refresh_cache(hostnames=["zanode.zorginstelling.nl"], synced_at="now")

    def test_assert_whitelisted_when_hostname_is_in_cache_does_not_raise(
        self,
        mocker: MockerFixture,
        faker: Faker,
    ) -> None:
        redis = mocker.Mock(spec=Redis)
        matching_hostname = faker.hostname()
        hostnames = [faker.hostname(), matching_hostname, faker.hostname()]

        redis.get.return_value = json.dumps(hostnames).encode()

        sut = RedisWhitelistRepository(redis=redis)

        sut.assert_whitelisted(matching_hostname)

        redis.get.assert_called_once_with(RedisWhitelistRepository.HOSTNAMES_CACHE_KEY)

    def test_assert_whitelisted_when_hostname_is_not_in_cache_raises_whitelist_error(
        self,
        mocker: MockerFixture,
        faker: Faker,
    ) -> None:
        redis = mocker.Mock(spec=Redis)
        hostnames = [faker.hostname(levels=1) for _ in range(3)]

        redis.get.return_value = json.dumps(hostnames).encode()

        sut = RedisWhitelistRepository(redis=redis)

        with pytest.raises(WhitelistError, match=r"^Hostname is not whitelisted"):
            sut.assert_whitelisted(faker.hostname(levels=2))

    def test_assert_whitelisted_with_unexpected_cache_state_raises_whitelist_error(
        self,
        mocker: MockerFixture,
        faker: Faker,
    ) -> None:
        redis = mocker.Mock(spec=Redis)

        redis.get.return_value = {"unexpected": "cache state"}

        sut = RedisWhitelistRepository(redis=redis)

        with pytest.raises(WhitelistError, match="Unexpected cache state"):
            sut.assert_whitelisted(faker.hostname())


class TestInMemoryWhitelistRepository:
    def test_assert_whitelisted_when_hostname_is_in_cache_does_not_raise(
        self,
        faker: Faker,
    ) -> None:
        sut = InMemoryWhitelistRepository()
        matching_hostname = faker.hostname()
        sut._InMemoryWhitelistRepository__hostnames = [matching_hostname]  # type: ignore[attr-defined]

        sut.assert_whitelisted(matching_hostname)

    def test_assert_whitelisted_when_hostname_is_not_in_cache_raises_whitelist_error(
        self,
        faker: Faker,
    ) -> None:
        sut = InMemoryWhitelistRepository()

        with pytest.raises(WhitelistError, match=r"^Hostname is not whitelisted"):
            sut.assert_whitelisted(faker.hostname())

    def test_refresh_cache_replaces_previous_hostnames(
        self,
        faker: Faker,
    ) -> None:
        sut = InMemoryWhitelistRepository()
        old_hostname = faker.hostname()
        sut._InMemoryWhitelistRepository__hostnames == [old_hostname]  # type: ignore[attr-defined]
        new_hostname = faker.hostname()

        sut.refresh_cache(
            hostnames=[new_hostname], synced_at=faker.date_time().isoformat()
        )

        assert sut._InMemoryWhitelistRepository__hostnames == [new_hostname]  # type: ignore[attr-defined]
