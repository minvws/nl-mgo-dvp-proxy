import json
from datetime import datetime

from app.medmij_logging.constants import DEFAULT_CLIENT_ID
from app.medmij_logging.enums import EventType, GrantType
from app.medmij_logging.schemas import EventData, RequestLogMessage, TokenRequestData


def test_it_converts_token_request_object_to_json_correctly() -> None:
    log_message = RequestLogMessage(
        event=EventData(
            datetime=datetime.fromisoformat("2024-12-18T15:51:40.425499+01:00"),
            location="https://dva.test.mgo.irealisatie.nl/",
            session_id="4edd2ed6-da43-458f-b5f0-efc0c07a91c4",
            trace_id="4edd2ed6-da43-458f-b5f0-efc0c07a91c4",
            type=EventType.SEND_TOKEN_REQUEST,
        ),
        request=TokenRequestData(
            id="52b336ac-cb87-4c1e-b9e8-545a58d7e0ea",
            method="GET",
            client_id="mgo-dvp-proxy",
            server_id="authorization-server.com",
            uri="https://authorization-server.com/auth/token",
            grant_type=GrantType.AUTHORIZATION_CODE,
            initiated_by="person",
        ),
    )
    expected_json = {
        "event": {
            "type": "send_token_request",
            "location": "https://dva.test.mgo.irealisatie.nl/",
            "datetime": "2024-12-18T15:51:40.425499+01:00",
            "session_id": "4edd2ed6-da43-458f-b5f0-efc0c07a91c4",
            "trace_id": "4edd2ed6-da43-458f-b5f0-efc0c07a91c4",
        },
        "request": {
            "id": "52b336ac-cb87-4c1e-b9e8-545a58d7e0ea",
            "method": "GET",
            "client_id": DEFAULT_CLIENT_ID,
            "server_id": "authorization-server.com",
            "uri": "https://authorization-server.com/auth/token",
            "grant_type": "authorization_code",
            "initiated_by": "person",
        },
    }

    # asserting it like this, might seem weird, but this is less prone to whitespace issues than comparing the strings directly
    assert json.loads(log_message.model_dump_json()) == expected_json


def test_it_converts_refresh_token_request_object_to_json_correctly() -> None:
    log_message = RequestLogMessage(
        event=EventData(
            datetime=datetime.fromisoformat("2024-12-18T15:51:40.425499+01:00"),
            location="https://dva.test.mgo.irealisatie.nl/",
            session_id="4edd2ed6-da43-458f-b5f0-efc0c07a91c4",
            trace_id="4edd2ed6-da43-458f-b5f0-efc0c07a91c4",
            type=EventType.SEND_TOKEN_REQUEST,
        ),
        request=TokenRequestData(
            id="52b336ac-cb87-4c1e-b9e8-545a58d7e0ea",
            method="GET",
            client_id=DEFAULT_CLIENT_ID,
            server_id="authorization-server.com",
            uri="https://authorization-server.com/auth/token",
            grant_type=GrantType.REFRESH_TOKEN,
            initiated_by="person",
        ),
    )

    expected_json = {
        "event": {
            "type": "send_token_request",
            "location": "https://dva.test.mgo.irealisatie.nl/",
            "datetime": "2024-12-18T15:51:40.425499+01:00",
            "session_id": "4edd2ed6-da43-458f-b5f0-efc0c07a91c4",
            "trace_id": "4edd2ed6-da43-458f-b5f0-efc0c07a91c4",
        },
        "request": {
            "id": "52b336ac-cb87-4c1e-b9e8-545a58d7e0ea",
            "method": "GET",
            "client_id": DEFAULT_CLIENT_ID,
            "server_id": "authorization-server.com",
            "uri": "https://authorization-server.com/auth/token",
            "grant_type": "refresh_token",
            "initiated_by": "person",
        },
    }

    assert json.loads(log_message.model_dump_json()) == expected_json
