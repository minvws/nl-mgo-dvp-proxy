from typing import Any, Dict

import httpx
import inject
from app.forwarding.constants import (
    MEDMIJ_REQUEST_ID_HEADER,
    MEDMIJ_CORRELATION_ID_HEADER,
)

from .exceptions import AuthorizationHttpException
from .interfaces import OauthTokenAdapter
from .models import AccessTokenDTO, AsyncOAuthClient


class MedMijOauthTokenAdapter(OauthTokenAdapter):
    GRANT_TYPE_ACCESS_TOKEN: str = "authorization_code"
    GRANT_TYPE_REFRESH_TOKEN: str = "refresh_code"

    @inject.autoparams()
    def __init__(
        self, client_id: str, redirect_uri: str, client: AsyncOAuthClient
    ) -> None:
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.client: AsyncOAuthClient = client

    async def __request_token_server(
        self,
        token_server_uri: str,
        params: dict[str, str],
        correlation_id: str,
        medmij_request_id: str,
    ) -> Dict[str, Any]:
        headers: dict[str, str] = {
            MEDMIJ_CORRELATION_ID_HEADER: correlation_id,
            MEDMIJ_REQUEST_ID_HEADER: medmij_request_id,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            response = await self.client.post(
                token_server_uri, data=params, headers=headers
            )
            response.raise_for_status()
            data: Dict[str, Any] = response.json()

        except httpx.HTTPStatusError as exc:
            raise AuthorizationHttpException(
                status_code=exc.response.status_code, detail=f"{str(exc)}"
            )
        except httpx.RequestError as exc:
            raise AuthorizationHttpException(
                status_code=500,
                detail={
                    "error": "MedMij Token Request failed",
                    "error_description": str(exc),
                },
            )
        return data

    async def get_access_token(
        self,
        token_server_uri: str,
        code: str,
        correlation_id: str,
        medmij_request_id: str,
    ) -> AccessTokenDTO:
        params: dict[str, str] = {
            "grant_type": self.GRANT_TYPE_ACCESS_TOKEN,
            "code": code,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
        }

        data: Dict[str, Any] = await self.__request_token_server(
            token_server_uri=token_server_uri,
            params=params,
            correlation_id=correlation_id,
            medmij_request_id=medmij_request_id,
        )

        access_token: AccessTokenDTO = AccessTokenDTO(
            access_token=str(data["access_token"]),
            token_type=str(data["token_type"]),
            expires_in=int(data["expires_in"]),
            refresh_token=str(data["refresh_token"]),
            scope=str(data["scope"]),
        )

        return access_token

    async def refresh_access_token(
        self,
        token_server_uri: str,
        refresh_token: str,
        correlation_id: str,
        medmij_request_id: str,
    ) -> AccessTokenDTO:
        params: dict[str, str] = {
            "grant_type": self.GRANT_TYPE_REFRESH_TOKEN,
            "refresh_token": refresh_token,
            "client_id": self.client_id,
        }

        data: Dict[str, Any] = await self.__request_token_server(
            token_server_uri=token_server_uri,
            params=params,
            correlation_id=correlation_id,
            medmij_request_id=medmij_request_id,
        )

        return AccessTokenDTO(
            access_token=str(data["access_token"]),
            token_type=str(data["token_type"]),
            expires_in=int(data["expires_in"]),
            refresh_token=str(data["refresh_token"]),
            scope=str(data["scope"]),
        )


class MockedOauthTokenAdapter(OauthTokenAdapter):
    def __init__(self, client_id: str) -> None:
        self.client_id = client_id

    async def get_access_token(
        self,
        token_server_uri: str,
        code: str,
        correlation_id: str,
        medmij_request_id: str,
    ) -> AccessTokenDTO:
        return AccessTokenDTO(
            access_token="mocked_access_token",
            token_type="Bearer",
            expires_in=900,
            refresh_token="mocked_refresh_token",
            scope="48 49",
        )

    async def refresh_access_token(
        self,
        token_server_uri: str,
        refresh_token: str,
        correlation_id: str,
        medmij_request_id: str,
    ) -> AccessTokenDTO:
        # Mocked implementation
        return AccessTokenDTO(
            access_token="mocked_access_token",
            token_type="Bearer",
            expires_in=900,
            refresh_token="mocked_refresh_token",
            scope="48 49",
        )
