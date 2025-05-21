from typing import Any, Dict

import pytest
from pydantic import ValidationError

from app.authentication.models import AccessTokenDTO, StateDTO


def test_access_token_dto_valid() -> None:
    data: Dict[str, Any] = {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
        "scope": "eenofanderezorgaanbieder",
    }
    access_token_dto = AccessTokenDTO(**data)
    assert access_token_dto.access_token == data["access_token"]
    assert access_token_dto.token_type == data["token_type"]
    assert access_token_dto.expires_in == data["expires_in"]
    assert access_token_dto.refresh_token == data["refresh_token"]
    assert access_token_dto.scope == data["scope"]


def test_access_token_dto_missing_field() -> None:
    data: Dict[str, Any] = {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
        # Missing "scope"
    }
    with pytest.raises(ValidationError, match="Field required"):
        AccessTokenDTO(**data)


def test_access_token_dto_empty_field() -> None:
    data: Dict[str, Any] = {
        "access_token": "",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
        "scope": "eenofanderezorgaanbieder",
    }
    with pytest.raises(
        ValidationError, match='Property "access_token" may not be empty'
    ):
        AccessTokenDTO(**data)


def test_state_dto_from_dict_with_expiration_time_string() -> None:
    state_dto = StateDTO.from_dict(
        {
            "expiration_time": "123",
            "correlation_id": "123",
            "token_endpoint_url": "https://example.com/token",
            "client_target_url": "https://example.com/callback",
        }
    )

    assert state_dto.expiration_time == 123


def test_state_dto_from_dict_with_expiration_time_none() -> None:
    state_dto = StateDTO.from_dict(
        {
            "correlation_id": "123",
            "token_endpoint_url": "https://example.com/token",
            "client_target_url": "https://example.com/callback",
        }
    )

    assert state_dto.expiration_time == None
