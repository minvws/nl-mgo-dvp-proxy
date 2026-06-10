from pathlib import Path

import pytest
from httpx import AsyncClient, AsyncHTTPTransport, Client, HTTPTransport

from app.config.models import OutboundProxyConfig, TlsConfig
from app.http_client.constants import PROXY_BYPASS_PATTERNS
from app.http_client.factories import AsyncClientFactory, SyncClientFactory


class TestAsyncClientFactory:
    @pytest.mark.anyio
    async def test_create_returns_async_client_with_redirects_enabled_by_default(
        self,
    ) -> None:
        client = AsyncClientFactory.create()

        assert isinstance(client, AsyncClient)
        assert client.follow_redirects is True

        await client.aclose()

    @pytest.mark.anyio
    async def test_create_can_disable_follow_redirects(self) -> None:
        client = AsyncClientFactory.create(follow_redirects=False)

        assert isinstance(client, AsyncClient)
        assert client.follow_redirects is False

        await client.aclose()

    def test_create_raises_for_invalid_proxy_url(self) -> None:
        """Testing this with a raises, so that we know the proxy_config is being respected"""
        with pytest.raises(ValueError, match="Unknown scheme for proxy URL"):
            AsyncClientFactory.create(
                proxy_config=OutboundProxyConfig(proxy_url="not-a-url")
            )

    def test_create_raises_for_missing_ca_cert_file(self, tmp_path: Path) -> None:
        """Testing this with a raises, so that we know the tls_config is being respected"""
        missing_ca_cert = tmp_path / "missing-ca.pem"

        with pytest.raises(FileNotFoundError, match="No such file or directory"):
            AsyncClientFactory.create(
                tls_config=TlsConfig(ca_cert=str(missing_ca_cert))
            )

    @pytest.mark.anyio
    async def test_create_without_proxy_has_no_bypass_mounts(self) -> None:
        client = AsyncClientFactory.create()

        mount_patterns = {k.pattern for k in client._mounts}
        for pattern in PROXY_BYPASS_PATTERNS:
            assert pattern not in mount_patterns

        await client.aclose()

    @pytest.mark.anyio
    async def test_create_with_proxy_has_bypass_mounts(self) -> None:
        client = AsyncClientFactory.create(
            proxy_config=OutboundProxyConfig(proxy_url="http://proxy.example.com:8080")
        )

        mount_transports = {k.pattern: t for k, t in client._mounts.items()}

        for pattern in PROXY_BYPASS_PATTERNS:
            assert pattern in mount_transports.keys()
            assert isinstance(mount_transports[pattern], AsyncHTTPTransport)

        await client.aclose()


class TestSyncClientFactory:
    def test_create_returns_sync_client_with_redirects_enabled_by_default(self) -> None:
        client = SyncClientFactory.create()

        assert isinstance(client, Client)
        assert client.follow_redirects is True

        client.close()

    def test_create_can_disable_follow_redirects(self) -> None:
        client = SyncClientFactory.create(follow_redirects=False)

        assert isinstance(client, Client)
        assert client.follow_redirects is False

        client.close()

    def test_create_raises_for_invalid_proxy_url(self) -> None:
        """Testing this with a raises, so that we know the proxy_config is being respected"""
        with pytest.raises(ValueError, match="Unknown scheme for proxy URL"):
            SyncClientFactory.create(
                proxy_config=OutboundProxyConfig(proxy_url="not-a-url")
            )

    def test_create_raises_for_missing_ca_cert_file(self, tmp_path: Path) -> None:
        """Testing this with a raises, so that we know the tls_config is being respected"""
        missing_ca_cert = tmp_path / "missing-ca.pem"

        with pytest.raises(FileNotFoundError, match="No such file or directory"):
            SyncClientFactory.create(tls_config=TlsConfig(ca_cert=str(missing_ca_cert)))

    def test_create_without_proxy_has_no_bypass_mounts(self) -> None:
        client = SyncClientFactory.create()

        mount_patterns = {k.pattern for k in client._mounts}
        for pattern in PROXY_BYPASS_PATTERNS:
            assert pattern not in mount_patterns

        client.close()

    def test_create_with_proxy_has_bypass_mounts(self) -> None:
        client = SyncClientFactory.create(
            proxy_config=OutboundProxyConfig(proxy_url="http://proxy.example.com:8080")
        )

        mount_transports = {k.pattern: t for k, t in client._mounts.items()}

        for pattern in PROXY_BYPASS_PATTERNS:
            assert pattern in mount_transports.keys()
            assert isinstance(mount_transports[pattern], HTTPTransport)

        client.close()
