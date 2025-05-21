from logging import Logger
from ssl import SSLContext
from typing import Any, Callable

from fastapi import HTTPException
from inject import autoparams
from requests import RequestException, Response, get, post

from app.config.models import VadHttpClientConfig

from .schemas import TokenGrantType, VadTokenResponse


class VadHttpClient:
    @autoparams()
    def __init__(
        self,
        config: VadHttpClientConfig,
        logger: Logger,
        ssl_context: SSLContext,
    ) -> None:
        self.__url: str = str(config.url)
        self.__logger = logger
        self.__default_request_kwargs = {
            "verify": ssl_context,
            "timeout": 5,
        }

    def get_oidc_config(self) -> Response:
        response = self.__make_web_request(
            get,
            f"{self.__url}/.well-known/openid-configuration",
        )

        return response

    def post_authz_code(
        self,
        endpoint: str,
        grant_type: TokenGrantType,
        authz_code: str,
        redirect_uri: str,
        code_verifier: str,
        client_id: str,
        client_assertion_type: str | None = None,
        client_assertion: str | None = None,
    ) -> VadTokenResponse:
        body = {
            "grant_type": grant_type,
            "code": authz_code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "client_id": client_id,
        }
        if client_assertion:
            body["client_assertion"] = client_assertion
        if client_assertion_type:
            body["client_assertion_type"] = client_assertion_type

        response = self.__make_web_request(
            post,
            f"{self.__url}{endpoint}",
            data=body,
        )

        return VadTokenResponse(**response.json())

    def get_userinfo(self, endpoint: str, access_token: str) -> Response:
        response = self.__make_web_request(
            get,
            f"{self.__url}{endpoint}",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        return response

    def __make_web_request(
        self, method: Callable[[str], Response], url: str, **request_kwargs: Any
    ) -> Response:
        request_kwargs.update(self.__default_request_kwargs)

        try:
            response: Response = method(url, **request_kwargs)
            response.raise_for_status()
        except RequestException as e:
            self.__logger.error("VAD Bad Request: %s", str(e))

            raise HTTPException(status_code=502, detail="VAD Bad Request")

        return response
