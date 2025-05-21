import sys
from os import path

from cryptography.fernet import Fernet

SECRET_NAME = "oidc-state.key"
DEFAULT_OUTPUT_PATH = path.abspath(path.join(path.dirname(__file__), "../secrets"))

output_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUTPUT_PATH

secret_key = Fernet.generate_key()

with open(path.join(output_path, SECRET_NAME), "w") as secret_key_file:
    secret_key_file.write(secret_key.decode())

print("Secret key written to", output_path)
