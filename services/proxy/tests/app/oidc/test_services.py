from json import dumps as json_encode
from time import time
from urllib.parse import parse_qs, urlsplit

from faker import Faker
from jwcrypto import jwk, jwt
from pytest import raises
from pytest_mock import MockerFixture

from app.config.models import OidcConfig
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
from app.security.repositories import KeyStoreRepository
from app.security.services import Encrypter

pvt_key_pem = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCvGGRblaTI7C/W
b0n8zNM5B/l0uJPAs6GhUr1tMU8AT2CKYULW7ddr5OpgbXg/Ghq4qFDW0s/gxAex
r7U6ArUwBacQyvrOqIhFskJGhGiJYgIiyLhLdfQEMakkQEtQDBfjnDlEDcUrQq41
OZfGTJRo4Ih6LgnsXBYS2VGwncHT4+1/JhV2NcnX632X7Wn8FYqTTsqvHhXmG/rC
iWqFAqDtkXDkxHOFrtp0RH30eoUlpvgW+yglfdxcqq66E/rpxwn+Sr/zwVZDwLIb
OJLxCGaik6pQ2KcivsPy2M3me6xB/N3K+LfK8fPt+JeSN+O/oIQxbwU9GquNIhli
eDLWGuSNAgMBAAECggEADCB5Wup7VjsdeRGOI0cgXfPScCYUfaUzTZQIcJaYrSHS
QuNHmNEyOVPKc9FBIcWyEhX+O1KweRW6nrDXsWPcnq3Vi1Ezm7qKbaFR+8ZR4yn5
keUq9nb95oh1+X/Gd43O3cHFKZR2km9011Tc0Swen0Dl0uh7YXZjRPzuLnhOo1kp
ltNazk61u/RMA7M179R7jvSbKvzdOFBvFXxoa21nb0qYu2mt4cL0Of7OmtvRcACx
02CBaR0LlwsOormJy0EoHdi/n3fE1nks28qIzpmQ1uHJKhCcNJtr5hD0g6++y/rY
C7Om5PSzKY0VDWuBSh5JwahUpRte8/Zo/ayiRiyhdQKBgQDVYimovqM6Q6MXC4vo
Kj+Jagb+9AIIUWdFh1+H56wVXELQcelkczGRjpXL3gyl/D6BwiEzGg5KyWzjhU/d
8iBsP/G4oq20mHaFlVmaVUa5Gr2RsR8L6yarBuPOTUaMlq50wo4ImRVA7LsmlM21
YUXm99fSKwdJZbTyl9POdWFR8wKBgQDSEKM4dAhSZ3Fnu6GnjI2Qnk0lmWFp12Pr
qWXmdYeQjEknlS4enSFMAIbmVTwqopq5cYpVDyHsJhIaENRTvlnkIXNI12ZL+9QN
rIoOJUubkfP8Ucr2WPKXSWuTN7vHpOWeExfpa/oiJ79aZsuLR9/IJgPPGt+MYP2J
00rjWGIPfwKBgH6mHrfLPrJsRrZ84fNQcBmtVq2oQjSRrEv2R1swxFCBTB7QHYjD
Xl5YVMyF5Nf32VnG0VG1W1pEJ177VyYSefAGHABMffE8tMwgkugpSSrAlleM2zKF
xZOpKTjfYMo8/RrMBuVPhu/cElCZ7WaEb6rg27YgV9jWhwmd19cokDTFAoGBAJrV
rJlF3YRvvsVJJeRL02TPaenW3liXbI0dtYBjDONco+dLLE1gYFSW5tgL52c9p3Ic
4GvF1aksfpc75GU9nyBqD4GXU02adzkE/lVi5BHtSLuoxkNCWL1uXp6KrByBzMXx
KOTis+JNDdxifJFTDv2GF7SmCDR+oSLf3Qkp8k2dAoGBAMo4zZDA4y+KZaBTLgtq
ztm58LvbWvfsK5soTx5y9Z6fxSIrlrv/BpAjuFgFZUZZRvMnXUInZNBb4SJh4g5H
1P4c27/IUOeSazWmgQxX6Gq/GwvxBSkgfIsS5DNePvffxbhc0cHWKTsXk5z/BkOF
ZKRQCoawdek33rFOfqndU2fQ
-----END PRIVATE KEY-----
"""
pub_key_pem = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArxhkW5WkyOwv1m9J/MzT
OQf5dLiTwLOhoVK9bTFPAE9gimFC1u3Xa+TqYG14PxoauKhQ1tLP4MQHsa+1OgK1
MAWnEMr6zqiIRbJCRoRoiWICIsi4S3X0BDGpJEBLUAwX45w5RA3FK0KuNTmXxkyU
aOCIei4J7FwWEtlRsJ3B0+PtfyYVdjXJ1+t9l+1p/BWKk07Krx4V5hv6wolqhQKg
7ZFw5MRzha7adER99HqFJab4FvsoJX3cXKquuhP66ccJ/kq/88FWQ8CyGziS8Qhm
opOqUNinIr7D8tjN5nusQfzdyvi3yvHz7fiXkjfjv6CEMW8FPRqrjSIZYngy1hrk
jQIDAQAB
-----END PUBLIC KEY-----
"""


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
    def test_create_returns_jwt(self, mocker: MockerFixture, faker: Faker) -> None:
        claims = {"iss": faker.uuid4()}
        pub_key: jwk.JWK = jwk.JWK.from_pem(
            pub_key_pem.encode(),
            password=None,
        )
        mock_key_store_repository = mocker.Mock(KeyStoreRepository)
        jwt_issuer = ClientAssertionJwtIssuer(mock_key_store_repository)

        mock_key_store_repository.get_key_store.side_effect = [
            [pvt_key_pem.encode()],
            [pub_key_pem.encode()],
        ]
        jwt_obj = jwt_issuer.create(claims)

        mock_key_store_repository.get_key_store.assert_has_calls(
            [mocker.call(ClientAssertionJwtIssuer.KEY_STORE_PVT_KEY_ID)],
            [mocker.call(ClientAssertionJwtIssuer.KEY_STORE_PUB_KEY_ID)],
        )
        jwt_check_claims = jwt.JWT(
            jwt=str(jwt_obj),
            key=pub_key,
            check_claims={
                **claims,
                "exp": int(time()),
            },
        )
        jwt_check_claims.validate(pub_key)

    def test_private_and_public_key_are_cached(self, mocker: MockerFixture) -> None:
        mock_key_store_repository = mocker.Mock(KeyStoreRepository)
        jwt_issuer = ClientAssertionJwtIssuer(
            key_store_repository=mock_key_store_repository,
        )

        mock_key_store_repository.get_key_store.side_effect = [
            [pvt_key_pem.encode()],
            [pub_key_pem.encode()],
        ]

        jwt_issuer.create({})
        jwt_issuer.create({})

        assert mock_key_store_repository.get_key_store.call_count == 2


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
    def test_invoke_returns_userinfo_response_with_correct_params(
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

        local_config = mocker.Mock(spec=OidcConfig)
        local_config.client_id = client_id
        local_config.callback_endpoint = callback_endpoint
        repository = mocker.Mock(spec=VadOidcConfigRepository)
        client = mocker.Mock(spec=VadHttpClient)
        jwt_issuer = mocker.Mock(spec=ClientAssertionJwtIssuer)
        provider = VadUserinfoProvider(
            base_url=base_url,
            config=local_config,
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
        assert (
            userinfo_url
            == f"{client_callback_url}?userinfo=eyJyaWQiOiJyaWQiLCJwZXJzb24iOnsiYWdlIjozNywibmFtZSI6eyJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSJ9fSwic3ViIjoiUk52bkF2T3B5RVZBb05HblZaUVUifQ=="
        )

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

        assert (
            userinfo_url
            == f"{client_callback_url}&userinfo=eyJyaWQiOiJyaWQiLCJwZXJzb24iOnsiYWdlIjozNywibmFtZSI6eyJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSJ9fSwic3ViIjoiUk52bkF2T3B5RVZBb05HblZaUVUifQ=="
        )
