from abc import ABC, abstractmethod

from app.authentication.models import AccessTokenDTO


class OauthTokenAdapter(ABC):
    @abstractmethod
    async def get_access_token(
        self,
        token_server_uri: str,
        code: str,
        correlation_id: str,
        medmij_request_id: str,
    ) -> AccessTokenDTO: ...  # pragma: no cover

    @abstractmethod
    async def refresh_access_token(
        self,
        token_server_uri: str,
        refresh_token: str,
        correlation_id: str,
        medmij_request_id: str,
    ) -> AccessTokenDTO: ...  # pragma: no cover
