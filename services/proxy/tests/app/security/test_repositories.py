from pathlib import Path

from faker import Faker
from jwcrypto.jwk import JWK
from pytest import raises

from app.security.repositories import (
    FilesystemJWKRepository,
    FilesystemSecretRepository,
)
from app.utils import root_path


class TestFilesystemSecretRepository:
    def test_adds_key_to_non_existing_store(self, faker: Faker) -> None:
        repository = FilesystemSecretRepository()
        key_store_id = faker.word()
        key = faker.word().encode()

        repository.add_key_to_store(key_store_id=key_store_id, key=key)

        assert repository._key_stores[key_store_id] == [key]

    def test_adds_key_to_existing_store(self, faker: Faker) -> None:
        repository = FilesystemSecretRepository()
        repository._key_stores = {faker.word(): [faker.word().encode()]}
        key_store_id = faker.word()
        key = faker.word().encode()

        repository.add_key_to_store(key_store_id=key_store_id, key=key)
        repository.add_key_to_store(key_store_id=key_store_id, key=key)

        assert len(repository._key_stores[key_store_id]) == 2
        assert repository._key_stores[key_store_id][1] == key

    def test_gets_existing_key_store(self, faker: Faker) -> None:
        repository = FilesystemSecretRepository()
        key_store_id = faker.word()
        key = faker.word().encode()
        repository._key_stores[key_store_id] = [key]

        assert repository.get_key_store(key_store_id) == [key]

    def test_raises_exception_when_key_store_does_not_exist(self, faker: Faker) -> None:
        repository = FilesystemSecretRepository()
        key_store_id = faker.word()

        with raises(KeyError, match=f"No key store found with ID: {key_store_id}"):
            repository.get_key_store(key_store_id)

    def test_raises_exception_when_key_store_is_empty(self, faker: Faker) -> None:
        repository = FilesystemSecretRepository()
        key_store_id = faker.word()
        repository._key_stores[key_store_id] = []

        with raises(KeyError, match=f"No keys found in key store {key_store_id}"):
            repository.get_key_store(key_store_id)

    def test_reads_key_from_file_and_adds_to_store(self, faker: Faker) -> None:
        repository = FilesystemSecretRepository()
        key_store_id = faker.word()

        repository.add_to_store_from_path(
            key_store_id=key_store_id,
            key_path=root_path(
                "tests/app/security/test_in_memory_key_store_repository.key"
            ),
        )

        assert key_store_id in repository._key_stores
        assert len(repository._key_stores[key_store_id]) > 0

    def test_raises_exception_when_file_does_not_exist(self, faker: Faker) -> None:
        repository = FilesystemSecretRepository()
        key_store_id = faker.word()

        with raises(FileNotFoundError):
            repository.add_to_store_from_path(
                key_store_id=key_store_id,
                key_path="non_existing.key",
            )

    def test_get_first_key_from_store_returns_first_key(self, faker: Faker) -> None:
        repository = FilesystemSecretRepository()
        key_store_id = faker.word()
        key1 = faker.word().encode()
        key2 = faker.word().encode()
        repository._key_stores[key_store_id] = [key1, key2]

        assert repository.get_first_key_from_store(key_store_id) == key1

    def test_get_first_key_from_store_raises_exception_when_store_empty(
        self, faker: Faker
    ) -> None:
        repository = FilesystemSecretRepository()
        key_store_id = faker.word()
        repository._key_stores[key_store_id] = []

        with raises(KeyError, match=f"No keys found in key store {key_store_id}"):
            repository.get_first_key_from_store(key_store_id)


class TestFilesystemJWKRepository:
    def test_adds_key_to_non_existing_store(self, faker: Faker) -> None:
        repository = FilesystemJWKRepository()
        key_store_id = faker.word()
        key = JWK.generate(kty="RSA", size=1024)

        repository.add_key_to_store(key_store_id=key_store_id, key=key)

        assert repository._key_stores[key_store_id] == [key]

    def test_adds_key_to_existing_store(self, faker: Faker) -> None:
        repository = FilesystemJWKRepository()
        key = JWK.generate(kty="RSA", size=1024)
        key_store_id = faker.word()
        repository._key_stores = {key_store_id: [JWK.generate(kty="RSA", size=1024)]}

        repository.add_key_to_store(key_store_id=key_store_id, key=key)

        assert len(repository._key_stores[key_store_id]) == 2
        assert repository._key_stores[key_store_id][1] == key

    def test_gets_key_from_store(self, faker: Faker) -> None:
        repository = FilesystemJWKRepository()
        key_store_id = faker.word()
        key = JWK.generate(kty="RSA", size=1024)
        repository._key_stores[key_store_id] = [key]

        assert repository.get_key_store(key_store_id)[0] == key

    def test_raises_exception_when_key_store_does_not_exist(self, faker: Faker) -> None:
        repository = FilesystemJWKRepository()
        key_store_id = faker.word()

        with raises(KeyError, match=f"No key store found with ID: {key_store_id}"):
            repository.get_key_store(key_store_id)

    def test_raises_exception_when_key_store_is_empty(self, faker: Faker) -> None:
        repository = FilesystemJWKRepository()
        key_store_id = faker.word()
        repository._key_stores[key_store_id] = []

        with raises(KeyError, match=f"No keys found in key store {key_store_id}"):
            repository.get_key_store(key_store_id)

    def test_add_to_store_from_path(self, tmp_path: Path, faker: Faker) -> None:
        repository = FilesystemJWKRepository()
        key_store_id = faker.word()
        with open(tmp_path / "test_key.pem", "wb") as key_file:
            key = JWK.generate(kty="RSA", size=1024)
            key_file.write(key.export_to_pem(private_key=True, password=None))

        repository.add_to_store_from_path(
            key_store_id=key_store_id, key_path=str(tmp_path / "test_key.pem")
        )

        assert key_store_id in repository._key_stores
        assert len(repository._key_stores[key_store_id]) > 0
        assert isinstance(repository._key_stores[key_store_id][0], JWK)

    def test_add_to_store_from_path_with_unsupported_mode(self, faker: Faker) -> None:
        repository = FilesystemJWKRepository()
        key_store_id = faker.word()

        with raises(ValueError, match="Unsupported import mode: unsupported_mode"):
            repository.add_to_store_from_path(
                key_store_id=key_store_id,
                key_path="test_key.pem",
                mode="unsupported_mode",  # type: ignore
            )

    def test_add_to_store_from_path_with_non_existing_file(self, faker: Faker) -> None:
        repository = FilesystemJWKRepository()
        key_store_id = faker.word()

        with raises(FileNotFoundError):
            repository.add_to_store_from_path(
                key_store_id=key_store_id, key_path="non_existing.pem"
            )

    def test_add_to_store_from_path_with_invalid_pem_file(
        self, tmp_path: Path, faker: Faker
    ) -> None:
        repository = FilesystemJWKRepository()
        key_store_id = faker.word()
        with open(tmp_path / "invalid_key.pem", "wb") as key_file:
            key_file.write(b"invalid pem content")

        with raises(ValueError, match=r"^Unable to load PEM file."):
            repository.add_to_store_from_path(
                key_store_id=key_store_id, key_path=str(tmp_path / "invalid_key.pem")
            )
