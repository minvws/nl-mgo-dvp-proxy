import os
from enum import Enum
from typing import Literal, Self, Set, TypeAlias, cast

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    Field,
    RootModel,
    field_validator,
)

from app.circuitbreaker.repositories import CircuitStateRepository


class InjectableConfig(BaseModel):
    pass


class Environment(str, Enum):  # pragma: no cover
    LOCAL = "local"
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class MetricAdapter(str, Enum):  # pragma: no cover
    NO_OP = "no-op"
    STATSD = "statsd"


class OidcClientAuthType(str, Enum):
    CLIENT_SECRET_POST = "client_secret_post"
    PRIVATE_KEY_JWT = "private_key_jwt"
    NONE = "none"


class NoOpMetricConfig(InjectableConfig):  # pragma: no cover
    adapter: Literal[MetricAdapter.NO_OP] = MetricAdapter.NO_OP


class StatsdMetricConfig(InjectableConfig):  # pragma: no cover
    adapter: Literal[MetricAdapter.STATSD] = MetricAdapter.STATSD
    host: str
    port: int
    prefix: str | None = None


class TlsConfig(BaseModel):  # pragma: no cover
    client_cert: str | None = None
    client_key: str | None = None
    ca_cert: str | None = None


class RetryConfig(InjectableConfig):
    max_retries: int = Field(ge=0)
    # Initial debounce (in seconds) before retrying request
    backoff: float = Field(gt=0)
    # Factor to increase each subsequent debounce by
    backoff_factor: float = Field(gt=0)


class CircuitBreaker(InjectableConfig):  # pragma: no cover
    fail_max: int = 5
    reset_timeout: int = 60
    state_storage: str = CircuitStateRepository.TYPE_IN_MEMORY

    def validate_state_storage(self) -> Self:
        if self.state_storage not in [
            CircuitStateRepository.TYPE_IN_MEMORY,
            CircuitStateRepository.TYPE_REDIS,
        ]:
            raise ValueError(
                f"Invalid value for 'state_storage': {self.state_storage}. Must be one of: {CircuitStateRepository.TYPE_IN_MEMORY}, {CircuitStateRepository.TYPE_REDIS}"
            )

        return self


class Redis(InjectableConfig):  # pragma: no cover
    host: str = Field(default="localhost")
    port: int = Field(default=6379)
    username: str = Field(default="")
    password: str = Field(default="")
    ssl: bool = Field(default=False)
    mutual_auth: bool = Field(default=False)
    ssl_certfile: str | None = Field(default=None)
    ssl_keyfile: str | None = Field(default=None)
    ssl_ca_certs: str | None = Field(default=None)

    def require_ssl_files_when_ssl_is_true(self) -> Self:
        if not self.ssl:
            return self

        required_files = [self.ssl_ca_certs]

        if self.mutual_auth:
            required_files.extend([self.ssl_certfile, self.ssl_keyfile])

        for file in required_files:
            if file is None:
                raise ValueError("SSL files are required when 'redis.ssl' is 'True'")

            if not os.path.isfile(file):
                raise ValueError(f"SSL file '{file}' does not exist")

        return self


class LoggingConfig(InjectableConfig):
    logger_name: str = "app"
    log_level: str = "DEBUG"


class OAuthConfig(InjectableConfig):
    # Oauth client id
    client_id: str
    # comma separated Oauth state signing keys, newest first, used in symmetric signing
    state_signing_key_paths: str
    # signature lifetime in seconds
    signature_lifetime_secs: int = 900
    # The URI the authorization server will redirect to after the user grants or denies access
    auth_redirect_uri: str
    # Enable/disable mocked oauth servers (auth, token)
    mock_oauth_servers: bool = False


class MedMijWhitelistConfig(InjectableConfig):
    url: str = Field(default="https://register.medmij.nl/MedMij_Whitelist.xml?api=2")
    pull_max_retries: int = Field(default=10, ge=0)
    pull_initial_backoff_secs: float = Field(default=0.5, gt=0)
    pull_backoff_factor: float = Field(default=2.0, gt=0)


class DvaTargetConfig(InjectableConfig):
    jwe_encryption_private_key: str
    jwt_signing_public_key: str
    host_blocklist: Set[str] = Field(default=["localhost", "127.0.0.1"])

    @field_validator("host_blocklist", mode="before")
    @classmethod
    def str_to_set(cls, v: str) -> set[str]:
        return set(v.split(",")) if v != "" else set()


class TelemetryConfig(InjectableConfig):
    enabled: bool = False
    service_name: str = Field("Proxy")
    collector_grpc_url: str = Field("http://jaeger:4317")


class OidcConfig(InjectableConfig):
    client_id: str
    callback_endpoint: str
    state_secret_path: str


class VadHttpClientConfig(InjectableConfig):
    url: AnyHttpUrl
    client_cert: str | None = None
    client_key: str | None = None
    ca_cert: str | None = None


class BaseUrl(RootModel[AnyHttpUrl]):
    @property
    def host(self) -> str:
        """
        The host part of the URL.
        """
        return cast(str, self.root.host)

    def __str__(self) -> str:
        return str(self.root)


class ForwardingConfig(InjectableConfig):
    require_provider_and_service_id: bool = False


class OidcClientSecretAuth(BaseModel):
    type: Literal[OidcClientAuthType.CLIENT_SECRET_POST] = (
        OidcClientAuthType.CLIENT_SECRET_POST
    )
    client_secret: str


class OidcClientJwtAuth(BaseModel):
    type: Literal[OidcClientAuthType.PRIVATE_KEY_JWT] = (
        OidcClientAuthType.PRIVATE_KEY_JWT
    )
    client_assertion_jwt_private_key_path: str
    client_assertion_jwt_public_key_path: str


class OidcClientNoAuth(BaseModel):
    type: Literal[OidcClientAuthType.NONE] = OidcClientAuthType.NONE


class OutboundProxyConfig(InjectableConfig):
    proxy_url: str | None = None


OidcClientAuth: TypeAlias = OidcClientSecretAuth | OidcClientJwtAuth | OidcClientNoAuth


class AppConfig(BaseModel):
    env: Environment
    logging: LoggingConfig = LoggingConfig()
    base_url: BaseUrl
    # Forwarding mTLS configuration
    tls: TlsConfig | None = None
    metric: StatsdMetricConfig | NoOpMetricConfig = Field(discriminator="adapter")
    retry: RetryConfig
    circuit_breaker: CircuitBreaker
    redis: Redis
    oauth: OAuthConfig
    # Shared MedMij mTLS configuration, used for OAuth and whitelist pulls
    medmij_tls: TlsConfig | None = None
    medmij_whitelist: MedMijWhitelistConfig = MedMijWhitelistConfig()
    dva_target: DvaTargetConfig
    telemetry: TelemetryConfig | None = None
    oidc: OidcConfig
    oidc_client_auth: OidcClientAuth = Field(discriminator="type")
    vad_http_client: VadHttpClientConfig
    forwarding: ForwardingConfig = ForwardingConfig()
    outbound_proxy: OutboundProxyConfig | None = None
