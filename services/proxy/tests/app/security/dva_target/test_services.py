from typing import Any, Callable, TypeAlias

from faker import Faker
from jwcrypto.jwk import JWK
from mgo_keystore_repositories import JWKRepository
from pytest import fixture, raises
from pytest_mock import MockerFixture

from app.security.dva_target.exceptions import (
    JWEDecryptError,
    JWTClaimsError,
    JWTValidationError,
)
from app.security.dva_target.services import DvaTargetAssertionParser
from tests.app.test_utils import create_jwe

JweFactoryType: TypeAlias = Callable[[Any, int | None, int], str]


class TestDvaTargetAssertionParser:
    @fixture
    def jwe_encryption_private_key(self) -> JWK:
        return JWK.generate(kty="RSA", size=2048)

    @fixture
    def jwe_encryption_public_key(self, jwe_encryption_private_key: JWK) -> JWK:
        return JWK.from_json(jwe_encryption_private_key.export_public())

    @fixture
    def jwt_signing_private_key(self) -> JWK:
        return JWK.generate(kty="EC", crv="P-256")

    @fixture
    def jwt_signing_public_key(self, jwt_signing_private_key: JWK) -> JWK:
        return JWK.from_json(jwt_signing_private_key.export_public())

    @fixture
    def error_context(self) -> dict[str, Any]:
        return {"field": "field_name"}

    @fixture
    def jwe_factory(
        self,
        jwe_encryption_public_key: JWK,
        jwt_signing_private_key: JWK,
    ) -> JweFactoryType:
        def _create_jwe(url: Any, iat: int | None, exp: int) -> str:
            return create_jwe(
                jwe_encryption_public_key=jwe_encryption_public_key,
                jwt_signing_private_key=jwt_signing_private_key,
                url=url,
                iat=iat,
                exp=exp,
            )

        return _create_jwe

    def test_parse_returns_dva_target_url(
        self,
        mocker: MockerFixture,
        faker: Faker,
        jwe_encryption_private_key: JWK,
        jwt_signing_public_key: JWK,
        jwe_factory: JweFactoryType,
    ) -> None:
        url = faker.url()
        serialized_jwe = jwe_factory(url, 0, 2147483647)
        mock_jwk_repository = mocker.Mock(spec=JWKRepository)

        mock_jwk_repository.get_first_key_from_store.side_effect = [
            jwe_encryption_private_key,
            jwt_signing_public_key,
        ]

        sut = DvaTargetAssertionParser(mock_jwk_repository, set())
        result = sut.parse(serialized_jwe, {})

        assert str(result) == url

        mock_jwk_repository.get_first_key_from_store.assert_has_calls(
            [
                mocker.call(DvaTargetAssertionParser.JWE_DECRYPTION_KID),
                mocker.call(DvaTargetAssertionParser.JWT_SIGNATURE_VALIDATION_KID),
            ]
        )

    def test_parse_fails_when_input_non_jwe(
        self,
        mocker: MockerFixture,
        error_context: dict[str, Any],
    ) -> None:
        mock_jwk_repository = mocker.Mock(spec=JWKRepository)

        with raises(JWEDecryptError, match=r"^Invalid format") as exc_info:
            sut = DvaTargetAssertionParser(mock_jwk_repository, set())
            sut.parse(
                serialized_jwe="this-is-not-a-jwe",
                error_context=error_context,
            )

        assert exc_info.value.error_context == error_context

    def test_parse_fails_when_jwe_cannot_decrypt(
        self,
        mocker: MockerFixture,
        faker: Faker,
        jwt_signing_private_key: JWK,
        jwt_signing_public_key: JWK,
        jwe_factory: JweFactoryType,
        error_context: dict[str, Any],
    ) -> None:
        serialized_jwe = jwe_factory(faker.url(), 0, 2147483647)
        mock_jwk_repository = mocker.Mock(spec=JWKRepository)

        mock_jwk_repository.get_first_key_from_store.side_effect = [
            jwt_signing_private_key,  # Wrong private key
            jwt_signing_public_key,
        ]

        with raises(
            JWEDecryptError,
            match=r"^No recipient matched the provided key",
        ) as exc_info:
            sut = DvaTargetAssertionParser(mock_jwk_repository, set())
            sut.parse(serialized_jwe, error_context)

        assert exc_info.value.error_context == error_context

        mock_jwk_repository.get_first_key_from_store.assert_called_once_with(
            DvaTargetAssertionParser.JWE_DECRYPTION_KID
        )

    def test_parse_fails_when_decrypted_jwt_exp_claim_invalid(
        self,
        mocker: MockerFixture,
        faker: Faker,
        jwe_encryption_private_key: JWK,
        jwt_signing_public_key: JWK,
        jwe_factory: JweFactoryType,
        error_context: dict[str, Any],
    ) -> None:
        serialized_jwe = jwe_factory(faker.url(), 0, 0)
        mock_jwk_repository = mocker.Mock(spec=JWKRepository)

        mock_jwk_repository.get_first_key_from_store.side_effect = [
            jwe_encryption_private_key,
            jwt_signing_public_key,
        ]

        with raises(JWTValidationError, match=r"^Expired at 0") as exc_info:
            sut = DvaTargetAssertionParser(mock_jwk_repository, set())
            sut.parse(serialized_jwe, error_context)

        assert exc_info.value.error_context == error_context

        mock_jwk_repository.get_first_key_from_store.assert_has_calls(
            [
                mocker.call(DvaTargetAssertionParser.JWE_DECRYPTION_KID),
                mocker.call(DvaTargetAssertionParser.JWT_SIGNATURE_VALIDATION_KID),
            ]
        )

    def test_parse_fails_when_decrypted_jwt_iat_claim_missing(
        self,
        mocker: MockerFixture,
        faker: Faker,
        jwe_encryption_private_key: JWK,
        jwt_signing_public_key: JWK,
        jwe_factory: JweFactoryType,
        error_context: dict[str, Any],
    ) -> None:
        serialized_jwe = jwe_factory(faker.url(), None, 2147483647)
        mock_jwk_repository = mocker.Mock(spec=JWKRepository)

        mock_jwk_repository.get_first_key_from_store.side_effect = [
            jwe_encryption_private_key,
            jwt_signing_public_key,
        ]

        with raises(JWTValidationError, match=r"^Claim iat is missing") as exc_info:
            sut = DvaTargetAssertionParser(mock_jwk_repository, set())
            sut.parse(serialized_jwe, error_context)

        assert exc_info.value.error_context == error_context

        mock_jwk_repository.get_first_key_from_store.assert_has_calls(
            [
                mocker.call(DvaTargetAssertionParser.JWE_DECRYPTION_KID),
                mocker.call(DvaTargetAssertionParser.JWT_SIGNATURE_VALIDATION_KID),
            ]
        )

    def test_parse_fails_when_decrypted_jwt_signature_invalid(
        self,
        mocker: MockerFixture,
        faker: Faker,
        jwe_encryption_private_key: JWK,
        jwe_encryption_public_key: JWK,
        jwe_factory: JweFactoryType,
        error_context: dict[str, Any],
    ) -> None:
        serialized_jwe = jwe_factory(faker.url(), 0, 2147483647)
        mock_jwk_repository = mocker.Mock(spec=JWKRepository)

        mock_jwk_repository.get_first_key_from_store.side_effect = [
            jwe_encryption_private_key,
            jwe_encryption_public_key,  # Wrong public key
        ]

        with raises(
            JWTValidationError,
            match=r"^Verification failed for all signatures",
        ) as exc_info:
            sut = DvaTargetAssertionParser(mock_jwk_repository, set())
            sut.parse(serialized_jwe, error_context)

        assert exc_info.value.error_context == error_context

        mock_jwk_repository.get_first_key_from_store.assert_has_calls(
            [
                mocker.call(DvaTargetAssertionParser.JWE_DECRYPTION_KID),
                mocker.call(DvaTargetAssertionParser.JWT_SIGNATURE_VALIDATION_KID),
            ]
        )

    def test_parse_fails_when_decrypted_jwt_url_claim_missing(
        self,
        mocker: MockerFixture,
        jwe_encryption_private_key: JWK,
        jwt_signing_public_key: JWK,
        jwe_factory: JweFactoryType,
        error_context: dict[str, Any],
    ) -> None:
        serialized_jwe = jwe_factory(None, 0, 2147483647)
        mock_jwk_repository = mocker.Mock(spec=JWKRepository)

        mock_jwk_repository.get_first_key_from_store.side_effect = [
            jwe_encryption_private_key,
            jwt_signing_public_key,
        ]

        with raises(JWTClaimsError, match="Missing 'url' claim in JWT") as exc_info:
            sut = DvaTargetAssertionParser(mock_jwk_repository, set())
            sut.parse(serialized_jwe, error_context)

        assert exc_info.value.error_context == error_context

        mock_jwk_repository.get_first_key_from_store.assert_has_calls(
            [
                mocker.call(DvaTargetAssertionParser.JWE_DECRYPTION_KID),
                mocker.call(DvaTargetAssertionParser.JWT_SIGNATURE_VALIDATION_KID),
            ]
        )

    def test_parse_fails_when_decrypted_jwt_url_claim_invalid(
        self,
        mocker: MockerFixture,
        jwe_encryption_private_key: JWK,
        jwt_signing_public_key: JWK,
        jwe_factory: JweFactoryType,
        error_context: dict[str, Any],
    ) -> None:
        serialized_jwe = jwe_factory(123, 0, 2147483647)
        mock_jwk_repository = mocker.Mock(spec=JWKRepository)

        mock_jwk_repository.get_first_key_from_store.side_effect = [
            jwe_encryption_private_key,
            jwt_signing_public_key,
        ]

        with raises(
            JWTClaimsError, match="The 'url' claim must be a string"
        ) as exc_info:
            sut = DvaTargetAssertionParser(mock_jwk_repository, set())
            sut.parse(serialized_jwe, error_context)

        assert exc_info.value.error_context == error_context

        mock_jwk_repository.get_first_key_from_store.assert_has_calls(
            [
                mocker.call(DvaTargetAssertionParser.JWE_DECRYPTION_KID),
                mocker.call(DvaTargetAssertionParser.JWT_SIGNATURE_VALIDATION_KID),
            ]
        )

    def test_parse_fails_when_dva_target_url_on_blocklist(
        self,
        mocker: MockerFixture,
        faker: Faker,
        jwe_encryption_private_key: JWK,
        jwt_signing_public_key: JWK,
        jwe_factory: JweFactoryType,
        error_context: dict[str, Any],
    ) -> None:
        disallowed_hostname = "malicious.host"
        url = f"https://{disallowed_hostname}/{faker.uri_path()}"
        serialized_jwe = jwe_factory(url, 0, 2147483647)
        mock_jwk_repository = mocker.Mock(spec=JWKRepository)

        mock_jwk_repository.get_first_key_from_store.side_effect = [
            jwe_encryption_private_key,
            jwt_signing_public_key,
        ]

        sut = DvaTargetAssertionParser(
            mock_jwk_repository, blocklist=set([disallowed_hostname])
        )

        with raises(JWTClaimsError, match="The DVA target host is blocked") as exc_info:
            sut.parse(serialized_jwe, error_context)

        assert exc_info.value.error_context == error_context

        mock_jwk_repository.get_first_key_from_store.assert_has_calls(
            [
                mocker.call(DvaTargetAssertionParser.JWE_DECRYPTION_KID),
                mocker.call(DvaTargetAssertionParser.JWT_SIGNATURE_VALIDATION_KID),
            ]
        )
