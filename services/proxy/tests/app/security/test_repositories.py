from faker import Faker
from pytest import raises

from app.security.repositories import (
    FilesystemKeyStoreRepository,
)
from app.utils import root_path


class TestFilesystemKeyStoreRepository:
    def test_adds_key_to_non_existing_store(self, faker: Faker) -> None:
        repository = FilesystemKeyStoreRepository()
        key_store_id = faker.word()
        key = faker.word().encode()

        repository.add_key_to_store(key_store_id=key_store_id, key=key)

        assert repository._key_stores[key_store_id] == [key]

    def test_adds_key_to_existing_store(self, faker: Faker) -> None:
        repository = FilesystemKeyStoreRepository()
        repository._key_stores = {faker.word(): [faker.word().encode()]}
        key_store_id = faker.word()
        key = faker.word().encode()

        repository.add_key_to_store(key_store_id=key_store_id, key=key)
        repository.add_key_to_store(key_store_id=key_store_id, key=key)

        assert len(repository._key_stores[key_store_id]) == 2
        assert repository._key_stores[key_store_id][1] == key

    def test_gets_existing_key_store(self, faker: Faker) -> None:
        repository = FilesystemKeyStoreRepository()
        key_store_id = faker.word()
        key = faker.word().encode()
        repository._key_stores[key_store_id] = [key]

        assert repository.get_key_store(key_store_id) == [key]

    def test_raises_exception_when_key_store_does_not_exist(self, faker: Faker) -> None:
        repository = FilesystemKeyStoreRepository()
        key_store_id = faker.word()

        with raises(KeyError, match=f"No key store found with ID: {key_store_id}"):
            repository.get_key_store(key_store_id)

    def test_raises_exception_when_key_store_is_empty(self, faker: Faker) -> None:
        repository = FilesystemKeyStoreRepository()
        key_store_id = faker.word()
        repository._key_stores[key_store_id] = []

        with raises(KeyError, match=f"No keys found in key store {key_store_id}"):
            repository.get_key_store(key_store_id)

    def test_reads_key_from_file_and_adds_to_store(self, faker: Faker) -> None:
        repository = FilesystemKeyStoreRepository()
        key_store_id = faker.word()

        repository.add_key_to_store_from_path(
            key_store_id=key_store_id,
            key_path=root_path(
                "tests/app/security/test_in_memory_key_store_repository.key"
            ),
        )

        assert key_store_id in repository._key_stores
        assert len(repository._key_stores[key_store_id]) > 0

    def test_raises_exception_when_file_does_not_exist(self, faker: Faker) -> None:
        repository = FilesystemKeyStoreRepository()
        key_store_id = faker.word()

        with raises(FileNotFoundError):
            repository.add_key_to_store_from_path(
                key_store_id=key_store_id,
                key_path="non_existing.key",
            )
