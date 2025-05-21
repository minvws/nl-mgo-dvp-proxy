import sys
from os import makedirs, path

from jwcrypto import jwk

PVT_KEY_NAME = "client_assertion_jwt.key"
PUB_KEY_NAME = "client_assertion_jwt.pem"
PVT_KEY_PATH_OPTION = "pvt-key-path"
PUB_KEY_PATH_OPTION = "pub-key-path"
DEFAULT_PVT_KEY_PATH = path.abspath(path.join(path.dirname(__file__), "../secrets"))
DEFAULT_PUB_KEY_PATH = path.abspath(path.join(path.dirname(__file__), "../secrets"))


def get_option_value(option: str) -> str | None:
    """
    Get the value of the option from the command line arguments.
    The option must be in the form --option=value; separate option and value will be ignored.

    :param option: The option to get the value for.
    :return: The value of the option
    """
    option = next((arg for arg in sys.argv if arg.startswith(f"--{option}=")), None)

    return option.split("=")[1] if option else None


pvt_key_path = get_option_value(PVT_KEY_PATH_OPTION) or DEFAULT_PVT_KEY_PATH
makedirs(pvt_key_path, exist_ok=True)

pub_key_path = get_option_value(PUB_KEY_PATH_OPTION) or DEFAULT_PUB_KEY_PATH
makedirs(pub_key_path, exist_ok=True)

pvt_key: jwk.JWK = jwk.JWK.generate(kty="RSA", size=2048)

with open(path.join(pvt_key_path, PVT_KEY_NAME), "w", encoding="utf-8") as pvt_key_file:
    pvt_key_file.write(pvt_key.export_to_pem(private_key=True, password=None).decode())

with open(path.join(pub_key_path, PUB_KEY_NAME), "w", encoding="utf-8") as pub_key_file:
    pub_key_file.write(pvt_key.export_to_pem(private_key=False, password=None).decode())

print(f"Private key {PVT_KEY_NAME} written to {pvt_key_path}")
print(f"Public key {PUB_KEY_NAME} written to {pub_key_path}")
