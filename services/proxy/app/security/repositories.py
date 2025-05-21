from abc import ABC, abstractmethod


class KeyStoreRepository(ABC):  # pragma: no cover
    @abstractmethod
    def add_key_to_store(self, key_store_id: str, key: bytes) -> None: ...

    @abstractmethod
    def get_key_store(self, key_store_id: str) -> list[bytes]: ...

    """
    :raises KeyError: If key store does not exist or is empty.
    """


class FilesystemKeyStoreRepository(KeyStoreRepository):
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

    def add_key_to_store_from_path(self, key_store_id: str, key_path: str) -> None:
        with open(key_path, "rb") as key_file:
            self.add_key_to_store(key_store_id, key_file.read())
