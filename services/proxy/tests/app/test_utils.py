import os
from typing import Any

import pytest
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

from app.utils import root_path


@pytest.mark.parametrize(
    "args, expected_relative_path",
    [
        (["data", "file.txt"], "data/file.txt"),
        (["config", "settings"], "config/settings"),
        ([], ""),
    ],
)
def test_root_path(args: list[str], expected_relative_path: str) -> None:
    test_dir = os.path.abspath(os.path.dirname(__file__))
    result = root_path(*args)
    expected_absolute_path = os.path.abspath(
        os.path.join(
            test_dir,
            "..",
            "..",
            expected_relative_path,
        ),
    )
    assert result == expected_absolute_path


def create_jwe(
    jwe_encryption_public_key: JWK,
    jwt_signing_private_key: JWK,
    url: Any,
    iat: int | None,
    exp: int,
) -> str:
    claims = {"exp": exp}
    if iat is not None:
        claims["iat"] = iat
    if url is not None:
        claims["url"] = url

    jwt_obj = JWT(header={"alg": "ES256"}, claims=claims)
    jwt_obj.make_signed_token(jwt_signing_private_key)

    jwe_obj = JWE(
        plaintext=jwt_obj.serialize().encode("utf-8"),
        protected='{"alg": "RSA-OAEP-256", "enc": "A256GCM"}',
    )
    jwe_obj.add_recipient(jwe_encryption_public_key)

    return jwe_obj.serialize(compact=True)
