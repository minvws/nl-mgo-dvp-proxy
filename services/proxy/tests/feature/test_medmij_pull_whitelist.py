import json
import logging
from pathlib import Path
from typing import Final, Generator, cast

import pytest
from click.testing import Result
from httpx import Client, MockTransport, Request, Response
from inject import Binder
from pytest_mock import MockerFixture, MockType
from redis import Redis
from typer.testing import CliRunner

from app.cli.main import command_line_app
from app.forwarding.client import RetryingSyncClient
from app.http_client.clients import SyncPkioMTLSClient
from app.medmij.repositories import RedisWhitelistRepository
from app.metrics.clients import NoOpMetricClient
from app.metrics.service import MetricService
from app.utils import root_path
from tests.utils import clear_bindings, configure_bindings

runner = CliRunner()

WHITELIST_STUB_PATH: Final[Path] = Path(
    root_path("tests", "feature", "stubs", "medmij", "whitelist.xml")
)
EXPECTED_HOSTNAMES: Final[list[str]] = [
    "medmij.deenigeechtepgo.nl",
    "pgocluster68.personalhealthprovider.net",
    "78834.umcharderwijk.nl",
    "medmij.za982.xisbridge.net",
    "medmij.za983.xisbridge.net",
    "medmij.xisbridge.net",
    "rcf-rso.nl",
]


class FileBackedResponseSequence:
    def __init__(self, response_file: Path, status_codes: list[int]) -> None:
        self.__response_file = response_file
        self.__status_codes = status_codes
        self.requests: list[Request] = []

    def __call__(self, request: Request) -> Response:
        self.requests.append(request)
        request_index = len(self.requests) - 1

        if request_index >= len(self.__status_codes):
            raise AssertionError("Unexpected extra whitelist request")

        return Response(
            status_code=self.__status_codes[request_index],
            text=self.__response_file.read_text(encoding="utf-8"),
            request=request,
        )


def assert_pull_succeeded(result: Result) -> None:
    assert result.exit_code == 0, result.output
    assert "Pulling MedMij whitelist hostnames" in result.output
    assert "Pulled 7 MedMij whitelist hostnames" in result.output


def assert_retry_was_used(
    response_sequence: FileBackedResponseSequence,
    caplog: pytest.LogCaptureFixture,
) -> None:
    request_methods = [request.method for request in response_sequence.requests]
    retry_log_messages = [record.message for record in caplog.records]

    assert request_methods == ["GET", "GET"]
    assert any("Request failed, retrying:" in message for message in retry_log_messages)


def assert_cache_refresh_was_atomic(
    redis: MockType,
    pipeline: MockType,
) -> None:
    hostnames_tmp_key = f"{RedisWhitelistRepository.HOSTNAMES_CACHE_KEY}:tmp"
    last_sync_tmp_key = f"{RedisWhitelistRepository.LAST_SYNC_CACHE_KEY}:tmp"
    serialized_hostnames = json.dumps(EXPECTED_HOSTNAMES)

    redis.pipeline.assert_called_once_with(transaction=True)

    assert [method_call[0] for method_call in pipeline.method_calls] == [
        "set",
        "set",
        "rename",
        "rename",
        "execute",
    ]

    hostname_set_call, synced_at_set_call = pipeline.set.call_args_list
    assert hostname_set_call.args == (hostnames_tmp_key, serialized_hostnames)
    assert synced_at_set_call.args[0] == last_sync_tmp_key
    assert isinstance(synced_at_set_call.args[1], str)
    assert synced_at_set_call.args[1] != ""

    rename_calls = [rename_call.args for rename_call in pipeline.rename.call_args_list]
    assert rename_calls == [
        (
            hostnames_tmp_key,
            RedisWhitelistRepository.HOSTNAMES_CACHE_KEY,
        ),
        (
            last_sync_tmp_key,
            RedisWhitelistRepository.LAST_SYNC_CACHE_KEY,
        ),
    ]

    pipeline.execute.assert_called_once_with()


@pytest.fixture
def pipeline(mocker: MockerFixture) -> MockType:
    return cast(MockType, mocker.Mock(name="redis_pipeline"))


@pytest.fixture
def redis(
    mocker: MockerFixture,
    pipeline: MockType,
) -> MockType:
    redis = cast(MockType, mocker.Mock(spec=Redis))
    redis.pipeline.return_value = pipeline
    return redis


@pytest.fixture
def response_sequence() -> FileBackedResponseSequence:
    return FileBackedResponseSequence(
        response_file=WHITELIST_STUB_PATH,
        status_codes=[503, 200],
    )


@pytest.fixture
def sync_client(
    response_sequence: FileBackedResponseSequence,
) -> Generator[Client, None, None]:
    sync_client = Client(transport=MockTransport(response_sequence))

    try:
        yield sync_client
    finally:
        sync_client.close()


@pytest.fixture
def retrying_client(
    sync_client: Client,
) -> RetryingSyncClient:
    return cast(
        RetryingSyncClient,
        RetryingSyncClient(
            sync_client=sync_client,
            metric_service=MetricService(metric_client=NoOpMetricClient()),
            max_retries=1,
            backoff=0.0,
            backoff_factor=1.0,
        ),
    )


def invoke_pull_whitelist_command(
    caplog: pytest.LogCaptureFixture,
    redis: MockType,
    retrying_client: RetryingSyncClient,
) -> Result:
    def bindings_override(binder: Binder) -> Binder:
        binder.bind(Redis, cast(Redis, redis))
        binder.bind(
            SyncPkioMTLSClient,
            cast(SyncPkioMTLSClient, retrying_client),
        )
        return binder

    target_logger = logging.getLogger("app.forwarding.client")

    configure_bindings(bindings_override=bindings_override)
    target_logger.addHandler(caplog.handler)
    caplog.set_level(logging.WARNING, logger="app.forwarding.client")
    caplog.clear()

    try:
        return runner.invoke(command_line_app, ["medmij", "pull-whitelist"])
    finally:
        target_logger.removeHandler(caplog.handler)
        clear_bindings()


def test_pull_whitelist_retries_and_refreshes_redis_cache_atomically(
    caplog: pytest.LogCaptureFixture,
    response_sequence: FileBackedResponseSequence,
    redis: MockType,
    pipeline: MockType,
    retrying_client: RetryingSyncClient,
) -> None:
    cli_result = invoke_pull_whitelist_command(
        caplog=caplog,
        redis=redis,
        retrying_client=retrying_client,
    )

    assert_pull_succeeded(cli_result)
    assert_retry_was_used(response_sequence, caplog)
    assert_cache_refresh_was_atomic(redis, pipeline)
