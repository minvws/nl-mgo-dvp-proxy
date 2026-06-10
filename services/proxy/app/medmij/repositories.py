import json
from abc import ABC, abstractmethod
from typing import Final, List
from urllib.error import URLError
from xml.etree.ElementTree import ParseError

import inject
import xmlschema
from redis import Redis
from xmlschema import XMLSchemaBase

from app.medmij.exceptions import WhitelistError


class XsdRepository(ABC):
    @abstractmethod
    def add_schema_to_cache(self, xsd_label: str, xsd_path: str) -> None: ...

    @abstractmethod
    def get_schema_from_cache(self, xsd_label: str) -> XMLSchemaBase: ...


class FilesystemWhitelistXsdRepository(XsdRepository):
    def __init__(self, xsd_cache: dict[str, XMLSchemaBase] = {}) -> None:
        self.__xsd_cache = xsd_cache

    def add_schema_to_cache(self, xsd_label: str, xsd_path: str) -> None:
        try:
            self.__xsd_cache[xsd_label] = xmlschema.XMLSchema(xsd_path)
        except (FileNotFoundError, URLError) as exception:
            raise ValueError(
                f"Could not load XSD schema '{xsd_label}': file not found at '{xsd_path}'"
            ) from exception
        except (xmlschema.XMLSchemaException, ParseError) as exception:
            raise ValueError(
                f"Could not load XSD schema '{xsd_label}': invalid XSD at '{xsd_path}'"
            ) from exception

    def get_schema_from_cache(self, xsd_label: str) -> XMLSchemaBase:
        try:
            return self.__xsd_cache[xsd_label]
        except KeyError as exception:
            raise KeyError(
                f"XSD schema '{xsd_label}' is not available in cache"
            ) from exception


class WhitelistRepository(ABC):
    @abstractmethod
    def refresh_cache(self, hostnames: List[str], synced_at: str) -> None: ...

    @abstractmethod
    def assert_whitelisted(self, hostname: str) -> None: ...


class InMemoryWhitelistRepository(WhitelistRepository):
    def __init__(self) -> None:
        self.__hostnames: List[str] = []

    def refresh_cache(self, hostnames: List[str], synced_at: str) -> None:
        _ = synced_at

        self.__hostnames = hostnames

    def assert_whitelisted(self, hostname: str) -> None:
        if hostname not in self.__hostnames:
            raise WhitelistError.because_hostname_not_whitelisted(hostname)


class RedisWhitelistRepository(WhitelistRepository):
    HOSTNAMES_CACHE_KEY: Final[str] = "medmij:whitelist:hostnames"
    LAST_SYNC_CACHE_KEY: Final[str] = "medmij:whitelist:last_sync"

    @inject.autoparams()
    def __init__(self, redis: Redis) -> None:
        self.__redis = redis

    def assert_whitelisted(self, hostname: str) -> None:
        cached = self.__redis.get(self.HOSTNAMES_CACHE_KEY)

        if cached is not None and not isinstance(cached, (str, bytes)):
            raise WhitelistError.because_unexpected_cache_state()

        hostnames: List[str] = json.loads(cached) if cached is not None else []

        if hostname not in hostnames:
            raise WhitelistError.because_hostname_not_whitelisted(hostname)

    def refresh_cache(self, hostnames: List[str], synced_at: str) -> None:
        self._atomically_refresh_cache(hostnames=hostnames, synced_at=synced_at)

    def _atomically_refresh_cache(self, hostnames: List[str], synced_at: str) -> None:
        temporary_hostnames_key = f"{self.HOSTNAMES_CACHE_KEY}:tmp"
        temporary_last_sync_key = f"{self.LAST_SYNC_CACHE_KEY}:tmp"

        pipeline = self.__redis.pipeline(transaction=True)
        pipeline.set(temporary_hostnames_key, json.dumps(hostnames))
        pipeline.set(temporary_last_sync_key, synced_at)
        pipeline.rename(temporary_hostnames_key, self.HOSTNAMES_CACHE_KEY)
        pipeline.rename(temporary_last_sync_key, self.LAST_SYNC_CACHE_KEY)
        pipeline.execute()
