import sys
from os import makedirs, path

from jwcrypto import jwk

TYPE_OPTION = "type"
NAME_OPTION = "name"
PATH_OPTION = "path"
DEFAULT_PATH = path.abspath(path.join(path.dirname(__file__), "../secrets"))


def get_option_value(option: str) -> str | None:
    """
    Get the value of the option from the command line arguments.
    The option must be in the form --option=value; separate option and value will be ignored.

    :param option: The option to get the value for.
    :return: The value of the option
    """
    option = next((arg for arg in sys.argv if arg.startswith(f"--{option}=")), "")

    return option.split("=")[1] if option else None


key_type = get_option_value(TYPE_OPTION) or "RSA"
key_name = get_option_value(NAME_OPTION) or "proxy"
key_path = get_option_value(PATH_OPTION) or DEFAULT_PATH

makedirs(key_path, exist_ok=True)

if key_type.upper() == "RSA":
    private_key = jwk.JWK.generate(kty="RSA", size=2048)
elif key_type.upper() == "EC":
    private_key = jwk.JWK.generate(kty="EC", crv="P-256")
else:
    raise ValueError(f"Unsupported key type: {key_type}. Supported types are: RSA, EC")

with open(path.join(key_path, f"{key_name}.key"), "w", encoding="utf-8") as private_key_file:
    private_key_file.write(private_key.export_to_pem(private_key=True, password=None).decode())

with open(path.join(key_path, f"{key_name}.pub"), "w", encoding="utf-8") as public_key_file:
    public_key_file.write(private_key.export_to_pem(private_key=False, password=None).decode())

print(f"Private key {key_name}.key written to {key_path}")
print(f"Public key {key_name}.pub written to {key_path}")
