from app.config.models import AppConfig, OidcClientJwtAuth
from app.oidc.services import ClientAssertionJwtIssuer
from app.security.dva_target.services import DvaTargetAssertionParser
from mgo_keystore_repositories import (
    FilesystemJWKRepository,
    FilesystemSecretRepository,
)
from app.security.services import FernetEncrypter


class JWKRepositorySeeder:
    @staticmethod
    def seed(repository: FilesystemJWKRepository, config: AppConfig) -> None:
        if isinstance(config.oidc_client_auth, OidcClientJwtAuth):
            repository.add_to_store_from_path(
                ClientAssertionJwtIssuer.KEY_STORE_PRIVATE_KEY_ID,
                config.oidc_client_auth.client_assertion_jwt_private_key_path,
            )
            repository.add_to_store_from_path(
                ClientAssertionJwtIssuer.KEY_STORE_PUBLIC_KEY_ID,
                config.oidc_client_auth.client_assertion_jwt_public_key_path,
            )

        repository.add_to_store_from_path(
            DvaTargetAssertionParser.JWE_DECRYPTION_KID,
            config.dva_target.jwe_encryption_private_key,
        )
        repository.add_to_store_from_path(
            DvaTargetAssertionParser.JWT_SIGNATURE_VALIDATION_KID,
            config.dva_target.jwt_signing_public_key,
        )


class SecretRepositorySeeder:
    @staticmethod
    def seed(repository: FilesystemSecretRepository, config: AppConfig) -> None:
        repository.add_to_store_from_path(
            FernetEncrypter.KEY_STORE_ID, config.oidc.state_secret_path
        )
