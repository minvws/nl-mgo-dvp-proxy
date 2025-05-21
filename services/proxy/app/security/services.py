import ssl

from abc import ABC, abstractmethod
from logging import Logger

from cryptography.fernet import Fernet, InvalidToken
from inject import autoparams

from .exceptions import CouldNotDecryptPayload
from .repositories import KeyStoreRepository


class Encrypter(ABC):  # pragma: no cover
    @abstractmethod
    def encrypt(self, payload: str) -> str:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: str) -> str:
        pass


class FernetEncrypter(Encrypter):
    KEY_STORE_ID: str = "fernet_secret"

    @autoparams()
    def __init__(self, key_store_repository: KeyStoreRepository, logger: Logger):
        self.__key_store_repository = key_store_repository
        self.__logger = logger

    def encrypt(self, payload: str) -> str:
        secret = self.__key_store_repository.get_key_store(self.KEY_STORE_ID)[0]
        fernet = Fernet(secret)

        return fernet.encrypt(payload.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        secrets = self.__key_store_repository.get_key_store(self.KEY_STORE_ID)

        for secret in secrets:
            try:
                fernet = Fernet(secret)

                return fernet.decrypt(ciphertext.encode()).decode()
            except InvalidToken as e:
                self.__logger.warning(e, exc_info=True)

        raise CouldNotDecryptPayload.because_failed_to_decrypt_ciphertext()


class SslContextFactory:
    @staticmethod
    def create(
        ca_cert: str | None, client_cert: str | None, client_key: str | None
    ) -> ssl.SSLContext | bool:
        if ca_cert is None:
            return False

        ssl_context = ssl.create_default_context(cafile=ca_cert)
        if client_cert and client_key:
            ssl_context.load_cert_chain(certfile=client_cert, keyfile=client_key)

        return ssl_context
