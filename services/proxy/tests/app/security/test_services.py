from base64 import urlsafe_b64encode
from os import urandom
from ssl import SSLContext

from cryptography.fernet import InvalidToken
from pytest import fixture, raises
from pytest_mock import MockerFixture, MockType

from app.security.exceptions import CouldNotDecryptPayload
from app.security.repositories import KeyStoreRepository
from app.security.services import FernetEncrypter, SslContextFactory


class TestFernetEncrypter:
    @fixture
    def mocks(
        self, mocker: MockerFixture
    ) -> tuple[FernetEncrypter, MockType, MockType]:
        mock_key_store_repository = mocker.Mock(KeyStoreRepository)
        mock_logger = mocker.Mock()

        fernet_encrypter = FernetEncrypter(mock_key_store_repository, mock_logger)

        return (fernet_encrypter, mock_key_store_repository, mock_logger)

    def test_encrypt_returns_decryptable_ciphertext(
        self, mocks: tuple[FernetEncrypter, MockType, MockType]
    ) -> None:
        (
            fernet_encrypter,
            mock_key_store_repository,
            _,
        ) = mocks
        secret_key = self.__generate_secret_key()

        mock_key_store_repository.get_key_store.return_value = [secret_key]

        ciphertext = fernet_encrypter.encrypt("payload")

        mock_key_store_repository.get_key_store.assert_called_once_with(
            FernetEncrypter.KEY_STORE_ID
        )
        assert fernet_encrypter.decrypt(ciphertext) == "payload"

    def test_decrypt_raises_error_when_ciphertext_could_not_be_decrypted(
        self, mocks: tuple[FernetEncrypter, MockType, MockType]
    ) -> None:
        fernet_encrypter, mock_key_store_repository, _ = mocks
        first_wrong_secret_key = self.__generate_secret_key()
        second_wrong_secret_key = self.__generate_secret_key()

        mock_key_store_repository.get_key_store.return_value = [
            first_wrong_secret_key,
            second_wrong_secret_key,
        ]

        with raises(CouldNotDecryptPayload, match="Failed to decrypt ciphertext"):
            fernet_encrypter.decrypt("some_ciphertext")

    def test_decrypt_logs_invalid_token_exception_as_warning(
        self, mocks: tuple[FernetEncrypter, MockType, MockType]
    ) -> None:
        fernet_encrypter, mock_key_store_repository, mock_logger = mocks
        wrong_secret_key = self.__generate_secret_key()
        correct_secret_key = self.__generate_secret_key()

        mock_key_store_repository.get_key_store.side_effect = [
            [correct_secret_key],
            [wrong_secret_key, correct_secret_key],
        ]
        ciphertext = fernet_encrypter.encrypt("payload")

        fernet_encrypter.decrypt(ciphertext)

        mock_logger.warning.assert_called_once()
        assert isinstance(mock_logger.warning.call_args[0][0], InvalidToken)

    def __generate_secret_key(self) -> str:
        return urlsafe_b64encode(urandom(32)).decode()


class TestSslContextCreator:
    def test_create_ssl_context_without_ca_cert(self) -> None:
        ssl_context_creator = SslContextFactory()
        ssl_context = ssl_context_creator.create(None, None, None)
        assert ssl_context is False

    def test_create_ssl_context_with_ca_cert(self, mocker: MockerFixture) -> None:
        ssl_context_creator = SslContextFactory()
        mock_ssl_context = mocker.Mock(spec=SSLContext)
        mocker.patch("ssl.create_default_context", return_value=mock_ssl_context)

        ssl_context = ssl_context_creator.create("/path/to/ca_cert.pem", None, None)
        assert isinstance(ssl_context, SSLContext)

    def test_create_ssl_context_with_client_cert_and_key(
        self, mocker: MockerFixture
    ) -> None:
        ca_cert = "/path/to/ca_cert.pem"
        client_cert = "/path/to/client_cert.pem"
        client_key = "/path/to/client_key.pem"
        ssl_context_creator = SslContextFactory()
        mock_ssl_context = mocker.Mock(spec=SSLContext)
        mocker.patch("ssl.create_default_context", return_value=mock_ssl_context)

        ssl_context = ssl_context_creator.create(ca_cert, client_cert, client_key)
        assert isinstance(ssl_context, SSLContext)
        mock_ssl_context.load_cert_chain.assert_called_once_with(
            certfile=client_cert, keyfile=client_key
        )
