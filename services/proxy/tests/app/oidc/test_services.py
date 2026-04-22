from base64 import urlsafe_b64decode
from json import dumps as json_encode
from json import loads as json_decode
from time import time
from urllib.parse import parse_qs, urlsplit

from faker import Faker
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from pytest import fixture, raises
from pytest_mock import MockerFixture

from app.config.models import (
    OidcClientJwtAuth,
    OidcClientNoAuth,
    OidcClientSecretAuth,
    OidcConfig,
)
from app.oidc.clients import VadHttpClient
from app.oidc.repositories import VadOidcConfigRepository
from app.oidc.schemas import (
    State,
    TokenGrantType,
    VadOidcConfiguration,
    VadTokenResponse,
    VadUserinfoResponse,
)
from app.oidc.services import (
    ClientAssertionJwtIssuer,
    ClientCallbackUrlDecorator,
    PkceCodePairGenerator,
    VadAuthorizationUrlProvider,
    VadUserinfoProvider,
)
from app.security.repositories import JWKRepository
from app.security.services import Encrypter


class TestPkceCodePairGenerator:
    def test_generate_returns_tuple_of_code_verifier_and_code_challenge(self) -> None:
        code_verifier, code_challenge = PkceCodePairGenerator().generate()

        assert len(code_verifier) == PkceCodePairGenerator.CODE_VERIFIER_LENGTH
        assert 43 <= len(code_challenge) <= 128

    def test_generate_raises_value_error_when_code_verifier_length_is_invalid(
        self,
    ) -> None:
        pkce_code_pair_generator = PkceCodePairGenerator()
        pkce_code_pair_generator.CODE_VERIFIER_LENGTH = 42

        with raises(
            ValueError,
            match="Code verifier must be between 43 and 128 characters long.",
        ):
            pkce_code_pair_generator.generate()


class TestClientAssertionJwtIssuer:
    @fixture
    def jwt_signing_private_key(self) -> JWK:
        return JWK.generate(kty="RSA", size=2048)

    @fixture
    def jwt_signing_public_key(self, jwt_signing_private_key: JWK) -> JWK:
        return JWK.from_json(jwt_signing_private_key.export_public())

    def test_create_returns_jwt(
        self,
        mocker: MockerFixture,
        faker: Faker,
        jwt_signing_private_key: JWK,
        jwt_signing_public_key: JWK,
    ) -> None:
        claims = {"iss": faker.uuid4()}
        mock_jwk_repository = mocker.Mock(JWKRepository)
        jwt_issuer = ClientAssertionJwtIssuer(mock_jwk_repository)

        mock_jwk_repository.get_first_key_from_store.side_effect = [
            jwt_signing_private_key,
            jwt_signing_public_key,
        ]
        jwt_obj = jwt_issuer.create(claims)

        mock_jwk_repository.get_first_key_from_store.assert_has_calls(
            [mocker.call(ClientAssertionJwtIssuer.KEY_STORE_PRIVATE_KEY_ID)],
            [mocker.call(ClientAssertionJwtIssuer.KEY_STORE_PUBLIC_KEY_ID)],
        )
        jwt_check_claims = JWT(
            jwt=str(jwt_obj),
            key=jwt_signing_public_key,
            check_claims={
                **claims,
                "exp": int(time()),
            },
        )
        jwt_check_claims.validate(jwt_signing_public_key)

    def test_private_and_public_key_are_cached(
        self,
        mocker: MockerFixture,
        jwt_signing_private_key: JWK,
        jwt_signing_public_key: JWK,
    ) -> None:
        mock_jwk_repository = mocker.Mock(JWKRepository)
        jwt_issuer = ClientAssertionJwtIssuer(
            jwk_repository=mock_jwk_repository,
        )

        mock_jwk_repository.get_first_key_from_store.side_effect = [
            jwt_signing_private_key,
            jwt_signing_public_key,
        ]

        jwt_issuer.create({})
        jwt_issuer.create({})

        assert mock_jwk_repository.get_first_key_from_store.call_count == 2


class TestVadAuthorizationUrlProvider:
    def test_invoke_returns_authz_url_with_correct_params(
        self, mocker: MockerFixture, faker: Faker
    ) -> None:
        client_id = str(faker.uuid4())
        base_url = "http://base.url/"
        callback_endpoint = "/callback"
        vad_oidc_config = VadOidcConfiguration(
            issuer=faker.uri(),
            authorization_endpoint=faker.uri(),
            token_endpoint=faker.uri(),
            scopes_supported=[faker.word()],
            response_types_supported=[faker.word()],
            response_modes_supported=[faker.word()],
            grant_types_supported=[faker.word()],
            subject_types_supported=[faker.word()],
            token_endpoint_auth_methods_supported=[faker.word()],
            claims_parameter_supported=faker.boolean(),
            userinfo_endpoint=faker.uri(),
        )
        client_callback_url = faker.uri()
        code_verifier = str(faker.sha256(raw_output=True))
        code_challenge = str(faker.sha256(raw_output=True))
        encrypted_state = "ciphertext"

        local_config = mocker.Mock(spec=OidcConfig)
        local_config.client_id = client_id
        local_config.callback_endpoint = callback_endpoint
        repository = mocker.Mock(spec=VadOidcConfigRepository)
        pkce = mocker.Mock(spec=PkceCodePairGenerator)
        encrypter = mocker.Mock(spec=Encrypter)
        provider = VadAuthorizationUrlProvider(
            base_url=base_url,
            config=local_config,
            vad_oidc_repository=repository,
            pkce_code_pair_generator=pkce,
            encrypter=encrypter,
        )

        repository.get_all.return_value = vad_oidc_config
        pkce.generate.return_value = (code_verifier, code_challenge)
        encrypter.encrypt.return_value = encrypted_state

        authorization_url = provider.invoke(client_callback_url)

        repository.get_all.assert_called_once()
        pkce.generate.assert_called_once()
        encrypter.encrypt.assert_called_once_with(
            json_encode(
                separators=(",", ":"),
                obj={
                    "client_callback_url": client_callback_url,
                    "code_verifier": code_verifier,
                },
            )
        )

        scheme, netloc, path, query, _ = urlsplit(authorization_url)
        query_params = parse_qs(query)

        assert f"{scheme}://{netloc}{path}" == vad_oidc_config.authorization_endpoint
        assert query_params["response_type"] == ["code"]
        assert query_params["client_id"] == [client_id]
        assert query_params["redirect_uri"] == ["http://base.url/callback"]
        assert query_params["scope"] == ["openid"]
        assert query_params["state"] == [encrypted_state]
        assert query_params["code_challenge"] == [code_challenge]
        assert query_params["code_challenge_method"] == ["S256"]
        assert len(query_params["nonce"][0]) == 32


class TestVadUserinfoProvider:
    def test_invoke_fetches_token_without_auth_and_returns_userinfo(
        self, mocker: MockerFixture, faker: Faker
    ) -> None:
        client_id = str(faker.uuid4())
        base_url = "http://base.url/"
        callback_endpoint = "/callback"
        vad_oidc_config = VadOidcConfiguration(
            issuer=faker.uri(),
            authorization_endpoint=faker.uri(),
            token_endpoint="http://oidc.issuer/token/endpoint",
            scopes_supported=[faker.word()],
            response_types_supported=[faker.word()],
            response_modes_supported=[faker.word()],
            grant_types_supported=[faker.word()],
            subject_types_supported=[faker.word()],
            token_endpoint_auth_methods_supported=[faker.word()],
            claims_parameter_supported=faker.boolean(),
            userinfo_endpoint="http://oidc.issuer/userinfo/endpoint",
        )
        authz_code = str(faker.sha256(raw_output=True))
        state = mocker.Mock(spec=State)
        state.code_verifier = str(faker.sha256(raw_output=True))
        access_token = str(faker.sha256(raw_output=True))
        client_userinfo_response = {
            "rid": str(faker.sha256(raw_output=True)),
            "person": {
                "age": faker.random_int(min=18, max=99),
                "name": {
                    "first_name": faker.first_name(),
                    "last_name": faker.last_name(),
                },
            },
            "sub": faker.pystr(),
        }

        oidc_config = mocker.Mock(spec=OidcConfig)
        oidc_config.client_id = client_id
        oidc_config.callback_endpoint = callback_endpoint
        oidc_client_auth_config = OidcClientNoAuth()
        repository = mocker.Mock(spec=VadOidcConfigRepository)
        client = mocker.Mock(spec=VadHttpClient)
        jwt_issuer = mocker.Mock(spec=ClientAssertionJwtIssuer)
        provider = VadUserinfoProvider(
            base_url=base_url,
            oidc_config=oidc_config,
            oidc_client_auth_config=oidc_client_auth_config,
            vad_oidc_repository=repository,
            vad_http_client=client,
            jwt_issuer=jwt_issuer,
        )

        repository.get_all.return_value = vad_oidc_config
        client.post_authz_code.return_value = VadTokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=faker.random_int(),
        )
        client.get_userinfo.return_value.json.return_value = client_userinfo_response

        userinfo_response = provider.invoke(authz_code, state)

        assert userinfo_response.model_dump() == client_userinfo_response
        repository.get_all.assert_called_once()
        client.post_authz_code.assert_called_once_with(
            endpoint="/token/endpoint",
            grant_type=TokenGrantType.AUTHZ_CODE,
            authz_code=authz_code,
            redirect_uri="http://base.url/callback",
            code_verifier=state.code_verifier,
            client_id=client_id,
        )
        jwt_issuer.create.assert_not_called()
        client.get_userinfo.assert_called_once_with(
            endpoint="/userinfo/endpoint", access_token=access_token
        )

    def test_invoke_fetches_token_using_jwt_auth_and_returns_userinfo(
        self, mocker: MockerFixture, faker: Faker
    ) -> None:
        client_id = str(faker.uuid4())
        base_url = "http://base.url/"
        callback_endpoint = "/callback"
        vad_oidc_config = VadOidcConfiguration(
            issuer=faker.uri(),
            authorization_endpoint=faker.uri(),
            token_endpoint="http://oidc.issuer/token/endpoint",
            scopes_supported=[faker.word()],
            response_types_supported=[faker.word()],
            response_modes_supported=[faker.word()],
            grant_types_supported=[faker.word()],
            subject_types_supported=[faker.word()],
            token_endpoint_auth_methods_supported=[faker.word()],
            claims_parameter_supported=faker.boolean(),
            userinfo_endpoint="http://oidc.issuer/userinfo/endpoint",
        )
        authz_code = str(faker.sha256(raw_output=True))
        state = mocker.Mock(spec=State)
        state.code_verifier = str(faker.sha256(raw_output=True))
        client_assertion_jwt = "client_assertion_jwt"
        access_token = str(faker.sha256(raw_output=True))
        client_userinfo_response = {
            "rid": str(faker.sha256(raw_output=True)),
            "person": {
                "age": faker.random_int(min=18, max=99),
                "name": {
                    "first_name": faker.first_name(),
                    "last_name": faker.last_name(),
                },
            },
            "sub": faker.pystr(),
        }

        oidc_config = mocker.Mock(spec=OidcConfig)
        oidc_config.client_id = client_id
        oidc_config.callback_endpoint = callback_endpoint
        oidc_client_auth_config = OidcClientJwtAuth(
            client_assertion_jwt_private_key_path="secrets/client_assertion_jwt.key",
            client_assertion_jwt_public_key_path="secrets/client_assertion_jwt.pem",
        )
        repository = mocker.Mock(spec=VadOidcConfigRepository)
        client = mocker.Mock(spec=VadHttpClient)
        jwt_issuer = mocker.Mock(spec=ClientAssertionJwtIssuer)
        provider = VadUserinfoProvider(
            base_url=base_url,
            oidc_config=oidc_config,
            oidc_client_auth_config=oidc_client_auth_config,
            vad_oidc_repository=repository,
            vad_http_client=client,
            jwt_issuer=jwt_issuer,
        )

        repository.get_all.return_value = vad_oidc_config
        jwt_issuer.create.return_value = client_assertion_jwt
        client.post_authz_code.return_value = VadTokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=faker.random_int(),
        )
        client.get_userinfo.return_value.json.return_value = client_userinfo_response

        userinfo_response = provider.invoke(authz_code, state)

        assert userinfo_response.model_dump() == client_userinfo_response
        repository.get_all.assert_called_once()
        client.post_authz_code.assert_called_once_with(
            endpoint="/token/endpoint",
            grant_type=TokenGrantType.AUTHZ_CODE,
            authz_code=authz_code,
            redirect_uri="http://base.url/callback",
            code_verifier=state.code_verifier,
            client_id=client_id,
            client_assertion=client_assertion_jwt,
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        )
        jwt_issuer.create.assert_called_once_with(
            {
                "iss": client_id,
                "sub": client_id,
                "aud": "http://oidc.issuer/token/endpoint",
            }
        )
        client.get_userinfo.assert_called_once_with(
            endpoint="/userinfo/endpoint", access_token=access_token
        )

    def test_invoke_fetches_token_using_secret_and_returns_userinfo(
        self, mocker: MockerFixture, faker: Faker
    ) -> None:
        client_id = str(faker.uuid4())
        client_secret = faker.uuid4()
        base_url = "http://base.url/"
        callback_endpoint = "/callback"
        vad_oidc_config = VadOidcConfiguration(
            issuer=faker.uri(),
            authorization_endpoint=faker.uri(),
            token_endpoint="http://oidc.issuer/token/endpoint",
            scopes_supported=[faker.word()],
            response_types_supported=[faker.word()],
            response_modes_supported=[faker.word()],
            grant_types_supported=[faker.word()],
            subject_types_supported=[faker.word()],
            token_endpoint_auth_methods_supported=[faker.word()],
            claims_parameter_supported=faker.boolean(),
            userinfo_endpoint="http://oidc.issuer/userinfo/endpoint",
        )
        authz_code = str(faker.sha256(raw_output=True))
        state = mocker.Mock(spec=State)
        state.code_verifier = str(faker.sha256(raw_output=True))
        access_token = str(faker.sha256(raw_output=True))

        client_userinfo_response = {
            "rid": str(faker.sha256(raw_output=True)),
            "person": {
                "age": faker.random_int(min=18, max=99),
                "name": {
                    "first_name": faker.first_name(),
                    "last_name": faker.last_name(),
                },
            },
            "sub": faker.pystr(),
        }
        oidc_config = mocker.Mock(spec=OidcConfig)
        oidc_config.client_id = client_id
        oidc_config.callback_endpoint = callback_endpoint
        oidc_client_auth_config = OidcClientSecretAuth(client_secret=client_secret)
        repository = mocker.Mock(spec=VadOidcConfigRepository)
        client = mocker.Mock(spec=VadHttpClient)
        jwt_issuer = mocker.Mock(spec=ClientAssertionJwtIssuer)
        provider = VadUserinfoProvider(
            base_url=base_url,
            oidc_config=oidc_config,
            oidc_client_auth_config=oidc_client_auth_config,
            vad_oidc_repository=repository,
            vad_http_client=client,
            jwt_issuer=jwt_issuer,
        )

        repository.get_all.return_value = vad_oidc_config
        client.post_authz_code.return_value = VadTokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=faker.random_int(),
        )
        client.get_userinfo.return_value.json.return_value = client_userinfo_response

        userinfo_response = provider.invoke(authz_code, state)

        assert userinfo_response.model_dump() == client_userinfo_response
        repository.get_all.assert_called_once()
        client.post_authz_code.assert_called_once_with(
            endpoint="/token/endpoint",
            grant_type=TokenGrantType.AUTHZ_CODE,
            authz_code=authz_code,
            redirect_uri="http://base.url/callback",
            code_verifier=state.code_verifier,
            client_id=client_id,
            client_secret=client_secret,
        )

        jwt_issuer.create.assert_not_called()
        client.get_userinfo.assert_called_once_with(
            endpoint="/userinfo/endpoint", access_token=access_token
        )


class TestClientUserinfoUrlProvider:
    def test_invoke_returns_url_with_query_params(
        self, mocker: MockerFixture, faker: Faker
    ) -> None:
        rid = "rid"
        age = 37
        first_name = "John"
        last_name = "Doe"
        userinfo = VadUserinfoResponse(
            rid=rid,
            person={
                "age": age,
                "name": {
                    "first_name": first_name,
                    "last_name": last_name,
                },
            },
            sub=faker.pystr(),
        )
        client_callback_url = faker.uri()
        state = mocker.Mock(spec=State)
        state.client_callback_url = client_callback_url

        userinfo_url = ClientCallbackUrlDecorator().decorate_with_userinfo_data(
            userinfo, state
        )

        assert "?" not in client_callback_url
        assert userinfo_url.startswith(f"{client_callback_url}?")

        query_params = parse_qs(urlsplit(userinfo_url).query)
        encoded_userinfo = query_params["userinfo"][0]
        decoded_userinfo = json_decode(urlsafe_b64decode(encoded_userinfo).decode())

        assert decoded_userinfo == userinfo.model_dump()

    def test_invoke_returns_url_with_additional_query_params(
        self, mocker: MockerFixture, faker: Faker
    ) -> None:
        rid = "rid"
        age = 37
        first_name = "John"
        last_name = "Doe"
        userinfo = VadUserinfoResponse(
            rid=rid,
            person={
                "age": age,
                "name": {
                    "first_name": first_name,
                    "last_name": last_name,
                },
            },
            sub=faker.pystr(),
        )
        client_callback_url = faker.uri() + "?foo=bar"
        state = mocker.Mock(spec=State)
        state.client_callback_url = client_callback_url

        userinfo_url = ClientCallbackUrlDecorator().decorate_with_userinfo_data(
            userinfo, state
        )

        assert userinfo_url.startswith(f"{client_callback_url}&")

        query_params = parse_qs(urlsplit(userinfo_url).query)
        encoded_userinfo = query_params["userinfo"][0]
        decoded_userinfo = json_decode(urlsafe_b64decode(encoded_userinfo).decode())

        assert decoded_userinfo == userinfo.model_dump()
