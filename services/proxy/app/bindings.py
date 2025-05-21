import configparser
import logging
import logging.config
from ssl import SSLContext
from typing import List

from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256
from httpx import AsyncClient
from inject import Binder
from redis import Redis
from statsd import StatsClient

from app.oidc.clients import VadHttpClient
from app.oidc.repositories import (
    VadOidcConfigRepository,
    WellKnownVadOidcConfigRepository,
)
from app.oidc.services import (
    ClientAssertionJwtIssuer,
    VadAuthorizationUrlProvider,
    VadUserinfoProvider,
)
from app.security.repositories import (
    FilesystemKeyStoreRepository,
    KeyStoreRepository,
)
from app.security.services import Encrypter, FernetEncrypter, SslContextFactory

from .authentication.adapters import MedMijOauthTokenAdapter, MockedOauthTokenAdapter
from .authentication.interfaces import OauthTokenAdapter
from .authentication.models import AsyncOAuthClient
from .authentication.services import (
    MedMijAuthRequestUrlDirector,
    StateService,
    UrlBuilder,
)
from .circuitbreaker.repositories import (
    CircuitStateRepository,
    InMemoryCircuitStateRepository,
    RedisCircuitStateRepository,
)
from .circuitbreaker.services import CircuitBreakerService
from .config.models import AppConfig, InjectableConfig, MetricAdapter, TlsConfig
from .config.services import ConfigParser
from .forwarding.client import AsyncClientRetryDecorator
from .forwarding.signing.services import SignedUrlVerifier
from .medmij_logging.factories import LogMessageFactory
from .medmij_logging.services import MedMijLogger
from .metrics.clients import MetricClient, NoOpMetricClient
from .utils import root_path
from .version.models import VersionInfo
from .version.services import read_version_info


def configure_bindings(binder: Binder, config_file: str) -> None:
    """
    Configure dependency bindings for the application.
    """
    app_config: AppConfig = __parse_app_config(config_file=config_file)
    binder.bind(AppConfig, app_config)
    logger = __bind_logger(binder, app_config)
    __bind_sub_configs(binder, app_config, logger)

    binder.bind(VersionInfo, read_version_info())
    # Make sure we get a new instance of the UrlBuilder for each injection
    binder.bind_to_constructor(UrlBuilder, UrlBuilder)

    __bind_metric_client(binder, app_config)
    __bind_async_client(binder, app_config.tls)
    __bind_async_oauth_client(binder, app_config.oauth_tls)
    __bind_signed_url_verifier(binder, app_config)
    __bind_circuit_breaker(binder, app_config)
    __bind_redis_connection(binder, app_config)
    __bind_state_service(binder, app_config)
    __bind_medmij_oauth_auth_url_builder(binder, app_config)
    __bind_medmij_oauth_token_adapter(binder, app_config)
    __bind_medmij_logging(binder, app_config)
    __bind_security(binder, app_config)
    __bind_oidc(binder, app_config)


def __parse_app_config(config_file: str) -> AppConfig:
    config_parser = ConfigParser(
        config_parser=configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation(),
        ),
        config_path=root_path(config_file),
    )
    return config_parser.parse()


def __bind_sub_configs(
    binder: Binder, app_config: AppConfig, logger: logging.Logger
) -> None:
    for _, value in app_config.__dict__.items():
        if isinstance(value, InjectableConfig) and value != None:
            logger.debug(f"Binding {type(value).__name__} to values {value}")
            binder.bind(type(value), value)


def __bind_logger(binder: Binder, app_config: AppConfig) -> logging.Logger:
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "uvicorn": {  # rewrites uvicorn.error to uvicorn
                    "format": "%(asctime)s - uvicorn - %(levelname)s - %(message)s"
                },
                "brief": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                },
                "precise": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s - %(pathname)s:%(lineno)s"
                },
                "json": {"()": "pythonjsonlogger.json.JsonFormatter"},
            },
            "handlers": {
                "uvicorn": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "uvicorn",
                    "level": app_config.logging.log_level,
                },
                "console.brief": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "brief",
                    "level": app_config.logging.log_level,
                },
                "console.precise": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "precise",
                    "level": app_config.logging.log_level,
                },
                "medmij": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "json",
                    "level": "INFO",
                },
            },
            "root": {
                "level": app_config.logging.log_level,
                "handlers": ["console.brief"],
            },
            "loggers": {
                "uvicorn.error": {
                    "level": "INFO",
                    "handlers": ["uvicorn"],
                    "propagate": False,
                },
                "uvicorn.access": {
                    "level": "INFO",
                    "handlers": ["console.brief"],
                    "propagate": False,
                },
                "medmij": {
                    "level": "INFO",
                    "handlers": ["medmij"],
                    "propagate": False,
                },
                app_config.logging.logger_name: {
                    "handlers": ["console.precise"],
                    "level": app_config.logging.log_level,
                    "propagate": False,
                },
            },
        }
    )

    logger = logging.getLogger(app_config.logging.logger_name)
    binder.bind(logging.Logger, logger)
    return logger


def __bind_metric_client(binder: Binder, app_config: AppConfig) -> None:
    if app_config.metric.adapter == MetricAdapter.NO_OP:
        metric_client = NoOpMetricClient()
    elif app_config.metric.adapter == MetricAdapter.STATSD:
        metric_client = StatsClient(
            app_config.metric.host, app_config.metric.port, app_config.metric.prefix
        )

    binder.bind(MetricClient, metric_client)


def __create_async_client(tls_config: TlsConfig | None) -> AsyncClient:
    verify: SSLContext | bool = False

    if tls_config is not None:
        verify = SslContextFactory.create(
            ca_cert=tls_config.ca_cert,
            client_cert=tls_config.client_cert,
            client_key=tls_config.client_key,
        )

    async_client = AsyncClient(
        verify=verify,
        follow_redirects=True,
    )

    return async_client


def __bind_async_client(binder: Binder, tls_config: TlsConfig | None) -> None:
    async_client: AsyncClient = __create_async_client(tls_config)

    binder.bind_to_constructor(
        AsyncClient,
        lambda: AsyncClientRetryDecorator(async_client=async_client),
    )


def __bind_async_oauth_client(binder: Binder, tls_config: TlsConfig | None) -> None:
    async_client: AsyncClient = __create_async_client(tls_config)

    binder.bind(AsyncOAuthClient, async_client)


def __bind_signed_url_verifier(binder: Binder, app_config: AppConfig) -> None:
    binder.bind(
        SignedUrlVerifier,
        SignedUrlVerifier(
            signature_algorithm=ECDSA(SHA256()),
            public_key_paths=[
                key
                for key in app_config.signature_validation.public_key_paths.split(",")
                if key != ""
            ],
        ),
    )


def __bind_circuit_breaker(binder: Binder, app_config: AppConfig) -> None:
    def __get_circuit_breaker_repository(
        app_config: AppConfig,
    ) -> CircuitStateRepository:
        if (
            app_config.circuit_breaker.state_storage
            == CircuitStateRepository.TYPE_REDIS
        ):
            # Type ignored because this class's constructor is decorated with @inject.autoparams which makes the return type Any
            return RedisCircuitStateRepository()  # type: ignore

        return InMemoryCircuitStateRepository()

    binder.bind_to_constructor(
        CircuitBreakerService,
        lambda: CircuitBreakerService(
            fail_max=app_config.circuit_breaker.fail_max,
            reset_timeout=app_config.circuit_breaker.reset_timeout,
            repository=__get_circuit_breaker_repository(app_config),
        ),
    )


def __bind_redis_connection(binder: Binder, app_config: AppConfig) -> None:
    redis = Redis(
        host=app_config.redis.host,
        port=app_config.redis.port,
        decode_responses=True,
        username=app_config.redis.username,
        password=app_config.redis.password,
        ssl=app_config.redis.ssl,
        ssl_certfile=app_config.redis.ssl_certfile
        if app_config.redis.mutual_auth
        else None,
        ssl_keyfile=app_config.redis.ssl_keyfile
        if app_config.redis.mutual_auth
        else None,
        ssl_ca_certs=app_config.redis.ssl_ca_certs if app_config.redis.ssl else None,
    )

    binder.bind(Redis, redis)


def __bind_state_service(binder: Binder, app_config: AppConfig) -> None:
    key_bytes: List[bytes] = []

    def load_key_and_construct(app_config: AppConfig) -> StateService:
        key_paths: list[str] = app_config.oauth.state_signing_key_paths.split(",")
        for state_signing_key_path in key_paths:
            key_bytes.append(open(state_signing_key_path, "rb").read())

        return StateService(
            signing_keys=key_bytes,
            signature_lifetime_secs=app_config.oauth.signature_lifetime_secs,
        )

    binder.bind(StateService, load_key_and_construct(app_config=app_config))


def __bind_medmij_oauth_auth_url_builder(binder: Binder, app_config: AppConfig) -> None:
    def create_medmij_oauth_request_url_builder(
        app_config: AppConfig,
    ) -> MedMijAuthRequestUrlDirector:
        return MedMijAuthRequestUrlDirector(  # type: ignore
            client_id=app_config.oauth.client_id,
            redirect_url=app_config.oauth.auth_redirect_uri,
        )

    binder.bind_to_constructor(
        MedMijAuthRequestUrlDirector,
        lambda: create_medmij_oauth_request_url_builder(app_config=app_config),
    )


def __bind_medmij_oauth_token_adapter(binder: Binder, app_config: AppConfig) -> None:
    def create_medmij_oauth_token_adapter(
        app_config: AppConfig,
    ) -> MedMijOauthTokenAdapter:
        if app_config.oauth_tls is None:
            raise ValueError(
                "TLS configuration is required for MedMijOauthTokenAdapter"
            )

        adapter: MedMijOauthTokenAdapter = MedMijOauthTokenAdapter(
            client_id=app_config.oauth.client_id,
            redirect_uri=app_config.oauth.auth_redirect_uri,
        )
        return adapter

    def create_mocked_oauth_token_adapter(
        app_config: AppConfig,
    ) -> MockedOauthTokenAdapter:
        return MockedOauthTokenAdapter(
            client_id=app_config.oauth.client_id,
        )

    binder.bind_to_constructor(
        OauthTokenAdapter,
        lambda: create_mocked_oauth_token_adapter(app_config=app_config)
        if app_config.oauth.mock_oauth_servers
        else create_medmij_oauth_token_adapter(app_config=app_config),
    )


def __bind_medmij_logging(binder: Binder, app_config: AppConfig) -> None:
    binder.bind_to_constructor(
        MedMijLogger,
        lambda: MedMijLogger(logging.getLogger("medmij")),
    )

    binder.bind_to_constructor(
        LogMessageFactory,
        lambda: LogMessageFactory(app_config.base_url),
    )


def __bind_oidc(binder: Binder, app_config: AppConfig) -> None:
    binder.bind_to_constructor(
        VadOidcConfigRepository, lambda: WellKnownVadOidcConfigRepository()
    )
    binder.bind_to_constructor(
        VadUserinfoProvider, lambda: VadUserinfoProvider(str(app_config.base_url))
    )
    binder.bind_to_constructor(
        VadAuthorizationUrlProvider,
        lambda: VadAuthorizationUrlProvider(str(app_config.base_url)),
    )

    binder.bind_to_constructor(
        VadHttpClient,
        lambda: VadHttpClient(
            ssl_context=SslContextFactory.create(
                ca_cert=app_config.vad_http_client.ca_cert,
                client_cert=app_config.vad_http_client.client_cert,
                client_key=app_config.vad_http_client.client_key,
            )
        ),
    )


def __bind_security(binder: Binder, app_config: AppConfig) -> None:
    binder.bind_to_constructor(Encrypter, lambda: FernetEncrypter())

    key_store_repository = FilesystemKeyStoreRepository()
    key_store_repository.add_key_to_store_from_path(
        FernetEncrypter.KEY_STORE_ID, app_config.oidc.state_secret_path
    )
    key_store_repository.add_key_to_store_from_path(
        ClientAssertionJwtIssuer.KEY_STORE_PVT_KEY_ID,
        app_config.oidc.client_assertion_jwt_pvt_key_path,
    )
    key_store_repository.add_key_to_store_from_path(
        ClientAssertionJwtIssuer.KEY_STORE_PUB_KEY_ID,
        app_config.oidc.client_assertion_jwt_pub_key_path,
    )

    binder.bind(KeyStoreRepository, key_store_repository)
