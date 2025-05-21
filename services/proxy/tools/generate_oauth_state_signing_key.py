import os
import sys
from cryptography import fernet


if len(sys.argv) > 1:
    path = sys.argv[1]

else:
    path = input("Where to save key? default: secrets/oauth_state_signing_key: ")

    if path == "":
        path = "secrets/oauth_state_signing_key.key"

if os.path.exists(path):
    if "--force" in sys.argv:
        print("Force flag detected. Overwriting existing file.")
    else:
        confirm = input("File already exists. Do you want to overwrite it? (y/n): ")

        if confirm.lower() != "y":
            print("Aborting. Key not saved.")
            sys.exit()

key = fernet.Fernet.generate_key()

if not os.path.exists(os.path.dirname(path)):
    os.makedirs(os.path.dirname(path), exist_ok=True)

with open(path, "wb") as f:
    f.write(key)

print(f"Key saved to {path}")
