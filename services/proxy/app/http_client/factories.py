import logging
from abc import ABC
from ssl import SSLContext

from httpx import AsyncClient, AsyncHTTPTransport, Client, HTTPTransport

from app.config.models import OutboundProxyConfig, TlsConfig
from app.http_client.constants import PROXY_BYPASS_PATTERNS
from app.security.services import SslContextFactory

logger = logging.getLogger(__name__)


class ClientFactory(ABC):
    @staticmethod
    def _resolve_verify(
        tls_config: TlsConfig | None,
    ) -> SSLContext | bool:
        verify: SSLContext | bool = False

        if tls_config is not None:
            verify = SslContextFactory.create(
                ca_cert=tls_config.ca_cert,
                client_cert=tls_config.client_cert,
                client_key=tls_config.client_key,
            )

        return verify

    @staticmethod
    def _resolve_proxy(
        proxy_config: OutboundProxyConfig | None,
    ) -> str | None:
        proxy: str | None = None

        if proxy_config is not None:
            proxy = proxy_config.proxy_url

        return proxy


class AsyncClientFactory(ClientFactory):
    @classmethod
    def create(
        cls,
        tls_config: TlsConfig | None = None,
        proxy_config: OutboundProxyConfig | None = None,
        follow_redirects: bool = True,
    ) -> AsyncClient:
        verify = cls._resolve_verify(tls_config=tls_config)
        proxy = cls._resolve_proxy(proxy_config=proxy_config)
        mounts = cls._resolve_mounts(proxy=proxy)

        return AsyncClient(
            verify=verify,
            follow_redirects=follow_redirects,
            proxy=proxy,
            mounts=mounts,
        )

    @staticmethod
    def _resolve_mounts(proxy: str | None) -> dict[str, AsyncHTTPTransport] | None:
        if proxy is None:
            return None

        return {
            pattern: AsyncHTTPTransport(proxy=None) for pattern in PROXY_BYPASS_PATTERNS
        }


class SyncClientFactory(ClientFactory):
    @classmethod
    def create(
        cls,
        tls_config: TlsConfig | None = None,
        proxy_config: OutboundProxyConfig | None = None,
        follow_redirects: bool = True,
    ) -> Client:
        verify = cls._resolve_verify(tls_config=tls_config)
        proxy = cls._resolve_proxy(proxy_config=proxy_config)
        mounts = cls._resolve_mounts(proxy=proxy)

        return Client(
            verify=verify,
            follow_redirects=follow_redirects,
            proxy=proxy,
            mounts=mounts,
        )

    @staticmethod
    def _resolve_mounts(proxy: str | None) -> dict[str, HTTPTransport] | None:
        if proxy is None:
            return None

        return {pattern: HTTPTransport(proxy=None) for pattern in PROXY_BYPASS_PATTERNS}
