from httpx import AsyncClient, Client


class AsyncPkioMTLSClient(AsyncClient):
    """This client is not suitable to use on the public internet."""

    ...


class SyncPkioMTLSClient(Client):
    """This client is not suitable to use on the public internet."""

    ...
