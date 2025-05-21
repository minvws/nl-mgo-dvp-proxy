from abc import ABC, abstractmethod
from json import loads as load_json

from inject import autoparams

from .clients import VadHttpClient
from .schemas import VadOidcConfiguration


class VadOidcConfigRepository(ABC):  # pragma: no cover
    @abstractmethod
    def get_all(self) -> VadOidcConfiguration: ...


class WellKnownVadOidcConfigRepository(VadOidcConfigRepository):
    @autoparams()
    def __init__(
        self,
        vad_http_client: VadHttpClient,
    ) -> None:
        self.__vad_http_client = vad_http_client
        self.__vad_oidc_config: VadOidcConfiguration | None = None

    def get_all(self) -> VadOidcConfiguration:
        return self.__get_or_fetch_vad_oidc_config()

    def __get_or_fetch_vad_oidc_config(self) -> VadOidcConfiguration:
        if self.__vad_oidc_config is None:
            response = self.__vad_http_client.get_oidc_config()
            self.__vad_oidc_config = VadOidcConfiguration(**load_json(response.text))

        return self.__vad_oidc_config
