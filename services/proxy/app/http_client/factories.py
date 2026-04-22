import logging
from ssl import SSLContext

from httpx import AsyncClient, AsyncHTTPTransport

from app.config.models import OutboundProxyConfig, TlsConfig
from app.http_client.constants import PROXY_BYPASS_PATTERNS
from app.security.services import SslContextFactory

logger = logging.getLogger(__name__)


class AsyncClientFactory:
    @staticmethod
    def create(
        tls_config: TlsConfig | None = None,
        proxy_config: OutboundProxyConfig | None = None,
        follow_redirects: bool = True,
    ) -> AsyncClient:
        verify: SSLContext | bool = False
        proxy: str | None = None
        mounts: dict[str, AsyncHTTPTransport] | None = None

        if tls_config is not None:
            verify = SslContextFactory.create(
                ca_cert=tls_config.ca_cert,
                client_cert=tls_config.client_cert,
                client_key=tls_config.client_key,
            )

        if proxy_config is not None:
            proxy = proxy_config.proxy_url
            if proxy is not None:
                mounts = AsyncClientFactory._create_proxy_bypass_mounts()

        return AsyncClient(
            verify=verify,
            follow_redirects=follow_redirects,
            proxy=proxy,
            mounts=mounts,
        )

    @staticmethod
    def _create_proxy_bypass_mounts() -> dict[str, AsyncHTTPTransport]:
        return {
            pattern: AsyncHTTPTransport(proxy=None) for pattern in PROXY_BYPASS_PATTERNS
        }
