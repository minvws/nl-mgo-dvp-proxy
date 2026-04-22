from typing import Protocol, TypeVar

from jwcrypto.jwk import JWK

from app.security.enums import JWKImportMode

T = TypeVar("T")


class KeyStoreRepository(Protocol[T]):
    def add_key_to_store(self, key_store_id: str, key: T) -> None: ...

    def get_key_store(self, key_store_id: str) -> list[T]: ...

    def get_first_key_from_store(self, key_store_id: str) -> T:
        return self.get_key_store(key_store_id)[0]


class JWKRepository(KeyStoreRepository[JWK]): ...


class SecretRepository(KeyStoreRepository[bytes]): ...


class FilesystemSecretRepository(SecretRepository):
    def __init__(self) -> None:
        self._key_stores: dict[str, list[bytes]] = {}

    def add_key_to_store(self, key_store_id: str, key: bytes) -> None:
        if self._key_stores.get(key_store_id) is None:
            self._key_stores[key_store_id] = [key]
        else:
            self._key_stores[key_store_id].append(key)

    def get_key_store(self, key_store_id: str) -> list[bytes]:
        if key_store_id not in self._key_stores:
            raise KeyError(f"No key store found with ID: {key_store_id}")

        if len(self._key_stores[key_store_id]) == 0:
            raise KeyError(f"No keys found in key store {key_store_id}")

        return self._key_stores[key_store_id]

    def add_to_store_from_path(self, key_store_id: str, key_path: str) -> None:
        with open(key_path, "rb") as key_file:
            self.add_key_to_store(key_store_id, key_file.read())


class FilesystemJWKRepository(JWKRepository):
    def __init__(self) -> None:
        self._key_stores: dict[str, list[JWK]] = {}

    def add_key_to_store(self, key_store_id: str, key: JWK) -> None:
        if self._key_stores.get(key_store_id) is None:
            self._key_stores[key_store_id] = [key]
        else:
            self._key_stores[key_store_id].append(key)

    def get_key_store(self, key_store_id: str) -> list[JWK]:
        if key_store_id not in self._key_stores:
            raise KeyError(f"No key store found with ID: {key_store_id}")

        if len(self._key_stores[key_store_id]) == 0:
            raise KeyError(f"No keys found in key store {key_store_id}")

        return self._key_stores[key_store_id]

    def add_to_store_from_path(
        self,
        key_store_id: str,
        key_path: str,
        mode: JWKImportMode = JWKImportMode.PEM,
    ) -> None:
        if mode != JWKImportMode.PEM:
            raise ValueError(f"Unsupported import mode: {mode}")

        with open(key_path, "rb") as key_file:
            jwk_obj = JWK.from_pem(key_file.read(), password=None)
            self.add_key_to_store(key_store_id, jwk_obj)
