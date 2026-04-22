from enum import Enum


class JWKImportMode(str, Enum):
    PEM = "pem"
    JSON = "json"
    PYCA = "pyca"
