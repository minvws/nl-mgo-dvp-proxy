import os
from enum import Enum
from typing import List, Literal, Self, cast

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


class OAuthTlsConfig(TlsConfig):  # pragma: no cover
    pass


class RetryConfig(InjectableConfig):
    max_retries: int = Field(ge=0)
    # Initial debounce (in seconds) before retrying request
    backoff: float = Field(gt=0)
    # Factor to increase each subsequent debounce by
    backoff_factor: float = Field(gt=0)


class SignatureValidationConfig(InjectableConfig):  # pragma: no cover
    # Feature flag to enable/disable signature validation
    verify_signed_requests: bool
    # A csv list of paths to public keys that can be used to verify signatures, these keys should correspond to the private keys in load
    public_key_paths: str


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


class DvaTargetConfig(InjectableConfig):
    host_blocklist: List[str] = Field(default=["localhost", "127.0.0.1"])

    @field_validator("host_blocklist", mode="before")
    @classmethod
    def str_to_list(cls, v: str) -> List[str]:
        return v.split(",") if v != "" else []


class TelemetryConfig(InjectableConfig):
    enabled: bool = False
    service_name: str = Field("Proxy")
    collector_grpc_url: str = Field("http://jaeger:4317")


class OidcConfig(InjectableConfig):
    client_id: str
    callback_endpoint: str
    state_secret_path: str
    client_assertion_jwt_pvt_key_path: str
    client_assertion_jwt_pub_key_path: str


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


class AppConfig(BaseModel):
    env: Environment
    logging: LoggingConfig = LoggingConfig()
    base_url: BaseUrl
    # Forwarding mTLS configuration
    tls: TlsConfig | None = None
    metric: StatsdMetricConfig | NoOpMetricConfig = Field(discriminator="adapter")
    retry: RetryConfig
    signature_validation: SignatureValidationConfig
    circuit_breaker: CircuitBreaker
    redis: Redis
    oauth: OAuthConfig
    # OAuth mTLS configuration
    oauth_tls: OAuthTlsConfig | None = None
    dva_target: DvaTargetConfig = DvaTargetConfig()
    telemetry: TelemetryConfig | None = None
    oidc: OidcConfig
    vad_http_client: VadHttpClientConfig
    forwarding: ForwardingConfig = ForwardingConfig()
