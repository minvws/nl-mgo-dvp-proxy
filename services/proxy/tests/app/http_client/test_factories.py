import pytest
from httpx import AsyncHTTPTransport

import app.http_client.factories as factories
from app.config.models import OutboundProxyConfig, TlsConfig
from app.http_client.constants import PROXY_BYPASS_PATTERNS
from app.http_client.factories import AsyncClientFactory
from app.security.services import SslContextFactory

"""
At first glance one might think, what are we actually testing here?
However, these tests ensure that the factory correctly interprets the configuration and passes the correct parameters to the constructor of the AsyncClient.
In this case we are using a stub to capture the parameters passed to the AsyncClient constructor.
"""


class StubAsyncClient:
    verify: bool
    follow_redirects: bool
    proxy: str | None
    mounts: dict[str, AsyncHTTPTransport] | None

    def __init__(
        self,
        *,
        verify: bool,
        follow_redirects: bool,
        proxy: str | None,
        mounts: dict[str, AsyncHTTPTransport] | None,
    ) -> None:
        self.verify = verify
        self.follow_redirects = follow_redirects
        self.proxy = proxy
        self.mounts = mounts


def _stub_async_client(
    monkeypatch: pytest.MonkeyPatch,
) -> type[StubAsyncClient]:
    monkeypatch.setattr(factories, "AsyncClient", StubAsyncClient)
    return StubAsyncClient


def test_forwards_proxy_url(monkeypatch: pytest.MonkeyPatch) -> None:
    StubAsyncClient = _stub_async_client(monkeypatch)
    proxy_url: str = "http://proxy.example.com:8080"
    proxy_config = OutboundProxyConfig(proxy_url=proxy_url)

    client = AsyncClientFactory.create(proxy_config=proxy_config)

    assert isinstance(client, StubAsyncClient)
    assert client.proxy == proxy_url
    assert client.verify is False
    assert client.mounts is not None
    assert sorted(client.mounts.keys()) == sorted(PROXY_BYPASS_PATTERNS)

    for mount in client.mounts.values():
        assert isinstance(mount, AsyncHTTPTransport)


def test_omits_proxy_when_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    StubAsyncClient = _stub_async_client(monkeypatch)

    client = AsyncClientFactory.create(proxy_config=None)

    assert isinstance(client, StubAsyncClient)
    assert client.proxy is None
    assert client.mounts is None


def test_omits_mounts_when_proxy_url_is_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    StubAsyncClient = _stub_async_client(monkeypatch)
    proxy_config = OutboundProxyConfig(proxy_url=None)

    client = AsyncClientFactory.create(proxy_config=proxy_config)

    assert isinstance(client, StubAsyncClient)
    assert client.proxy is None
    assert client.mounts is None


def test_uses_tls_context(monkeypatch: pytest.MonkeyPatch) -> None:
    StubAsyncClient = _stub_async_client(monkeypatch)
    verify_context = object()

    tls_config = TlsConfig(
        ca_cert="ca.pem", client_cert="cert.pem", client_key="key.pem"
    )

    def fake_create(*, ca_cert: str, client_cert: str, client_key: str) -> object:
        assert (ca_cert, client_cert, client_key) == (
            "ca.pem",
            "cert.pem",
            "key.pem",
        )
        return verify_context

    monkeypatch.setattr(SslContextFactory, "create", fake_create)
    client = AsyncClientFactory.create(tls_config=tls_config)

    assert isinstance(client, StubAsyncClient)
    assert client.verify is verify_context


@pytest.mark.parametrize("follow_redirects", [True, False])
def test_respects_follow_redirects_flag(
    monkeypatch: pytest.MonkeyPatch, follow_redirects: bool
) -> None:
    StubAsyncClient = _stub_async_client(monkeypatch)

    client = AsyncClientFactory.create(follow_redirects=follow_redirects)

    assert isinstance(client, StubAsyncClient)
    assert client.follow_redirects is follow_redirects
