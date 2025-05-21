import base64
from builtins import ExceptionGroup
from logging import Logger

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256
from pytest_mock import MockerFixture

from app.forwarding.models import DvaTarget, TargetUrlSignature
from app.forwarding.signing.exceptions import (
    DisallowedTargetHost,
    InvalidTargetUrlSignature,
    MissingTargetUrlSignature,
    SigningKeyNotLoaded,
)
from app.forwarding.signing.services import DvaTargetVerifier, SignedUrlVerifier
from tests.utils import load_app_config

valid_key_1 = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzlBW/Ow5zqy7bEkn9n1Lk0SW48z9
h/ztNAojUa5cIyco6paHLF4Sk2sn8aYoAowaAGuRLf8wp2GutNI5H9qwIQ==
-----END PUBLIC KEY-----
"""

valid_key_2 = b"""-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEU7wljGq0NiF/AjEBME9+XfPzF90FIuH2
Z8/aQKfYZmB9GaH0fF4w7ciFQb4W7dG9Dd3NbbZ8+v4qZ4H1JxpyG0kj8Iwdo7+4
AvCImkB5ZZMQRgVUlOF+HBF8Xg9Al8jG
-----END PUBLIC KEY-----
"""

invalid_key = b"""-----BEGIN PUBLIC KEY-----
InvalidKeyData
-----END PUBLIC KEY-----
"""


@pytest.mark.anyio
class TestSignedUrlVerifier:
    @pytest.fixture
    def valid_key_1(self) -> bytes:
        return valid_key_1

    @pytest.fixture
    def valid_key_2(self) -> bytes:
        return valid_key_2

    @pytest.fixture
    def invalid_key(self) -> bytes:
        return invalid_key

    async def test_initialize_without_public_key_paths(self) -> None:
        """
        Test initialization of the service without public key paths.
        Ensures the service initializes without raising an exception.
        """
        signed_url_verifier = SignedUrlVerifier(
            signature_algorithm=ECDSA(SHA256()),
            public_key_paths=[],
        )
        assert signed_url_verifier.public_keys == []

    async def test_load_valid_keys(self, mocker: MockerFixture) -> None:
        """
        Test loading of valid public keys.
        Ensures keys are loaded and stored correctly in the service.
        """
        mock_load_pem_public_key = mocker.patch(
            "cryptography.hazmat.primitives.serialization.load_pem_public_key"
        )

        mock_public_key = mocker.Mock(spec=ec.EllipticCurvePublicKey)
        mock_load_pem_public_key.return_value = mock_public_key

        mock_file = mocker.patch("anyio.open_file", new_callable=mocker.AsyncMock)
        mock_file.return_value.__aenter__.return_value.read = mocker.AsyncMock(
            return_value=valid_key_1,
        )

        signed_url_verifier = SignedUrlVerifier(
            signature_algorithm=ECDSA(SHA256()),
            public_key_paths=["dummy_path_1.pem", "dummy_path_2.pem"],
        )
        await signed_url_verifier.load_public_keys()

        assert len(signed_url_verifier.public_keys) == 2
        assert isinstance(signed_url_verifier.public_keys[0], ec.EllipticCurvePublicKey)

    async def test_load_invalid_key_data(self, mocker: MockerFixture) -> None:
        """
        Test loading of invalid public key data.
        Ensures the service raises ValueError for invalid key data.
        """
        mock_load_pem_public_key = mocker.patch(
            "cryptography.hazmat.primitives.serialization.load_pem_public_key"
        )

        mock_file = mocker.patch("anyio.open_file", new_callable=mocker.AsyncMock)
        mock_file.return_value.__aenter__.return_value.read = mocker.AsyncMock(
            return_value=b"Invalid PEM"
        )

        mock_load_pem_public_key.side_effect = ValueError("Invalid key data")
        signed_url_verifier = SignedUrlVerifier(
            signature_algorithm=ECDSA(SHA256()),
            public_key_paths=["dummy_path.pem"],
        )

        with pytest.raises(ExceptionGroup) as excinfo:
            await signed_url_verifier.load_public_keys()

        assert any(isinstance(e, ValueError) for e in excinfo.value.exceptions)

    async def test_verify_with_invalid_signature(self, mocker: MockerFixture) -> None:
        """
        Test verification of a signed endpoint with an invalid signature.
        Ensures the service raises CannotVerifySignature for an invalid signature.
        """
        mock_file = mocker.patch("anyio.open_file", new_callable=mocker.AsyncMock)
        mock_file.return_value.__aenter__.return_value.read = mocker.AsyncMock(
            return_value=valid_key_1
        )
        signed_url_verifier = SignedUrlVerifier(
            signature_algorithm=ECDSA(SHA256()),
            public_key_paths=["dummy_path.pem"],
        )
        dummy_signature = base64.urlsafe_b64encode(b"invalid").decode()

        await signed_url_verifier.load_public_keys()
        with pytest.raises(InvalidTargetUrlSignature):
            signed_url_verifier.verify(
                "http://example.com/api/data",
                TargetUrlSignature(dummy_signature),
            )

    async def test_verify_with_valid_signature(self, mocker: MockerFixture) -> None:
        """
        Test direct signature verification with a valid signature.
        Ensures the service successfully verifies a valid signature.
        """
        mock_file = mocker.patch("anyio.open_file", new_callable=mocker.AsyncMock)
        mock_file.return_value.__aenter__.return_value.read = mocker.AsyncMock(
            return_value=valid_key_1
        )
        algorithm = ECDSA(SHA256())
        signed_url_verifier = SignedUrlVerifier(
            signature_algorithm=algorithm,
            public_key_paths=["dummy_path.pem"],
        )
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        signed_url_verifier.public_keys = [public_key]

        endpoint = "http://example.com/api/data"

        signed_signature = private_key.sign(endpoint.encode(), algorithm)
        encoded_signature = base64.urlsafe_b64encode(signed_signature).decode()

        signature = TargetUrlSignature(encoded_signature)

        signed_url_verifier.verify(endpoint, signature)

    async def test_load_multiple_keys(self, mocker: MockerFixture) -> None:
        """
        Test loading multiple public keys.
        Ensures all provided keys are loaded correctly.
        """
        mock_load_pem_public_key = mocker.patch(
            "cryptography.hazmat.primitives.serialization.load_pem_public_key"
        )

        mock_file = mocker.patch("anyio.open_file", new_callable=mocker.AsyncMock)
        mock_file.side_effect = [
            mocker.AsyncMock(return_value=valid_key_1),
            mocker.AsyncMock(return_value=valid_key_2),
        ]
        mock_load_pem_public_key.side_effect = [
            mocker.Mock(spec=ec.EllipticCurvePublicKey),
            mocker.Mock(spec=ec.EllipticCurvePublicKey),
        ]
        signed_url_verifier = SignedUrlVerifier(
            signature_algorithm=ECDSA(SHA256()),
            public_key_paths=["dummy_path_1.pem", "dummy_path_2.pem"],
        )
        await signed_url_verifier.load_public_keys()
        assert len(signed_url_verifier.public_keys) == 2
        assert isinstance(signed_url_verifier.public_keys[0], ec.EllipticCurvePublicKey)
        assert isinstance(signed_url_verifier.public_keys[1], ec.EllipticCurvePublicKey)

    async def test_verify_signature_with_mismatched_signature(
        self, mocker: MockerFixture
    ) -> None:
        """
        Test direct signature verification with a mismatched signature.
        Ensures the service raises CannotVerifySignature for a mismatched signature.
        """
        mock_file = mocker.patch("anyio.open_file", new_callable=mocker.AsyncMock)
        mock_file.return_value.__aenter__.return_value.read = mocker.AsyncMock(
            return_value=valid_key_1
        )
        signed_url_verifier = SignedUrlVerifier(
            signature_algorithm=ECDSA(SHA256()),
            public_key_paths=["dummy_path.pem"],
        )
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        signed_url_verifier.public_keys = [public_key]

        endpoint = "http://example.com/api/data"
        raw_signature = private_key.sign(
            b"other_data",
            ec.ECDSA(hashes.SHA256()),
        )
        with pytest.raises(InvalidTargetUrlSignature):
            signed_url_verifier.verify(
                endpoint,
                TargetUrlSignature(
                    base64.urlsafe_b64encode(raw_signature).decode(),
                ),
            )

    async def test_load_invalid_pem(self, mocker: MockerFixture) -> None:
        """
        Test loading of an invalid PEM key.
        Ensures the service raises ValueError for invalid PEM data.
        """
        mock_load_pem_public_key = mocker.patch(
            "cryptography.hazmat.primitives.serialization.load_pem_public_key"
        )
        mock_file = mocker.patch("anyio.open_file", new_callable=mocker.AsyncMock)
        mock_file.return_value.__aenter__.return_value.read = mocker.AsyncMock(
            return_value=invalid_key
        )
        mock_load_pem_public_key.side_effect = ValueError("Invalid PEM data")
        signed_url_verifier = SignedUrlVerifier(
            signature_algorithm=ECDSA(SHA256()),
            public_key_paths=["dummy_path.pem"],
        )
        with pytest.raises(ExceptionGroup) as excinfo:
            await signed_url_verifier.load_public_keys()
            assert any(isinstance(e, ValueError) for e in excinfo.value.exceptions)

    async def test_verify_signature_with_invalid_signature(
        self, mocker: MockerFixture
    ) -> None:
        """
        Test direct signature verification with an invalid signature.
        Ensures the service raises CannotVerifySignature for an invalid signature.
        """
        mock_file = mocker.patch("anyio.open_file", new_callable=mocker.AsyncMock)
        mock_file.return_value.__aenter__.return_value.read = mocker.AsyncMock(
            return_value=valid_key_1
        )
        signed_url_verifier = SignedUrlVerifier(
            signature_algorithm=ECDSA(SHA256()),
            public_key_paths=["dummy_path.pem"],
        )
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        signed_url_verifier.public_keys = [public_key]

        endpoint = "http://example.com/api/data"

        with pytest.raises(InvalidTargetUrlSignature):
            signed_url_verifier.verify(
                endpoint,
                TargetUrlSignature("invalid_signature"),
            )

    async def test_verify_signature_with_unexpected_exception(
        self, mocker: MockerFixture
    ) -> None:
        """
        Test direct signature verification handling of unexpected exceptions.
        Ensures the service raises CannotVerifySignature when an unexpected exception occurs.
        """
        mock_load_pem_public_key = mocker.patch(
            "cryptography.hazmat.primitives.serialization.load_pem_public_key"
        )
        mock_public_key = mocker.Mock(spec=ec.EllipticCurvePublicKey)
        mock_load_pem_public_key.return_value = mock_public_key

        mock_file = mocker.patch("anyio.open_file", new_callable=mocker.AsyncMock)
        mock_file.return_value.__aenter__.return_value.read = mocker.AsyncMock(
            return_value=valid_key_1
        )

        signed_url_verifier = SignedUrlVerifier(
            signature_algorithm=ECDSA(SHA256()),
            public_key_paths=["dummy_path.pem"],
        )
        await signed_url_verifier.load_public_keys()

        mocker.patch.object(
            signed_url_verifier.public_keys[0],
            "verify",
            side_effect=Exception("Unexpected error"),
        )
        with pytest.raises(InvalidTargetUrlSignature) as excinfo:
            signed_url_verifier.verify("data", TargetUrlSignature("signature"))
        assert "Unexpected error" in str(excinfo.value)

    async def test_load_public_key_invalid_type(self, mocker: MockerFixture) -> None:
        """
        Test loading of a non-EllipticCurvePublicKey.
        Ensures the service raises TypeError when the loaded key is not of the expected type.
        """
        mock_load_pem_public_key = mocker.patch(
            "cryptography.hazmat.primitives.serialization.load_pem_public_key"
        )

        mock_open = mocker.patch("anyio.open_file", new_callable=mocker.AsyncMock)
        mock_open.return_value.__aenter__.return_value.read = mocker.AsyncMock(
            return_value=valid_key_1
        )
        loaded_key = mocker.Mock()
        mock_load_pem_public_key.return_value = loaded_key

        signed_url_verifier = SignedUrlVerifier(
            signature_algorithm=ECDSA(SHA256()),
            public_key_paths=["dummy_path.pem"],
        )
        with pytest.raises(TypeError):
            await signed_url_verifier._load_public_key("dummy_path.pem")

    @pytest.mark.anyio
    async def test_load_keys_does_not_attempt_to_load_keys_when_keys_already_loaded(
        self, mocker: MockerFixture
    ) -> None:
        signed_url_verifier = SignedUrlVerifier(
            signature_algorithm=ECDSA(SHA256()),
            public_key_paths=[],
        )

        signed_url_verifier.public_keys = [mocker.Mock()]
        spy = mocker.spy(signed_url_verifier, "_load_public_key")

        await signed_url_verifier.load_public_keys()
        assert spy.call_count == 0

    @pytest.mark.anyio
    async def test_verify_without_loaded_keys_raises_signing_key_not_loaded(
        self, mocker: MockerFixture
    ) -> None:
        config = load_app_config()
        config.signature_validation.verify_signed_requests = True
        config.signature_validation.public_key_paths = ""

        signed_url_verifier = SignedUrlVerifier(
            signature_algorithm=ECDSA(SHA256()),
            public_key_paths=[],
        )

        with pytest.raises(SigningKeyNotLoaded):
            signed_url_verifier.verify(
                "http://example.com/api/data",
                mocker.Mock(TargetUrlSignature),
            )


class TestDvaTargetVerifier:
    @pytest.mark.anyio
    async def test_verify_with_empty_signature(self, mocker: MockerFixture) -> None:
        config = load_app_config()
        config.signature_validation.verify_signed_requests = True

        dva_target_verifier = DvaTargetVerifier(
            app_config=config,
            signed_url_verifier=mocker.Mock(spec=SignedUrlVerifier),
            logger=mocker.Mock(Logger),
        )

        dva_target = DvaTarget(target_url="http://example.com/api/data", signature=None)

        with pytest.raises(MissingTargetUrlSignature):
            await dva_target_verifier.verify(dva_target)

    @pytest.mark.anyio
    async def test_skip_verification_of_signed_url_if_feature_flag_is_disabled(
        self, mocker: MockerFixture
    ) -> None:
        config = load_app_config()
        config.signature_validation.verify_signed_requests = False

        logger = mocker.Mock(Logger)

        dva_target_verifier = DvaTargetVerifier(
            app_config=config,
            signed_url_verifier=mocker.Mock(spec=SignedUrlVerifier),
            logger=logger,
        )

        dva_target = DvaTarget(
            target_url="http://example.com/api/data",
            signature=TargetUrlSignature("sgOCLRLH26Y/Q/nqt6yUqA=="),
        )

        await dva_target_verifier.verify(dva_target)

        logger.info.assert_any_call(
            "Skipped verification of dva target url",
        )

    @pytest.mark.anyio
    async def test_ignore_missing_signature_if_feature_is_disabled(
        self, mocker: MockerFixture
    ) -> None:
        config = load_app_config()
        config.signature_validation.verify_signed_requests = False

        logger = mocker.Mock(Logger)

        dva_target_verifier = DvaTargetVerifier(
            app_config=config,
            signed_url_verifier=mocker.Mock(spec=SignedUrlVerifier),
            logger=logger,
        )

        dva_target = DvaTarget(
            target_url="http://example.com/api/data",
            signature=None,
        )

        await dva_target_verifier.verify(dva_target)

        logger.info.assert_any_call(
            "Ignored missing signature from dva target url",
        )

    @pytest.mark.anyio
    async def test_verify_raises_exception_if_dva_target_host_is_disallowed(
        self, mocker: MockerFixture
    ) -> None:
        config = load_app_config()
        config.dva_target.host_blocklist = ["example.com"]
        dva_target = DvaTarget(
            target_url="http://example.com/api/data",
            signature=None,
        )
        dva_target_verifier = DvaTargetVerifier(
            app_config=config,
            signed_url_verifier=mocker.Mock(),
        )

        with pytest.raises(
            DisallowedTargetHost,
            match="DVA target host 'example.com' is disallowed by the blocklist",
        ):
            await dva_target_verifier.verify(dva_target)
