from __future__ import annotations

import base64

from .constants import TARGET_URL_SIGNATURE_QUERY_PARAM


class TargetUrlSignature:
    def __init__(self, value: str) -> None:
        self.value = value

    def decode(self) -> bytes:
        return base64.urlsafe_b64decode(self.value.encode())


class DvaTarget:
    def __init__(
        self,
        target_url: str,
        signature: TargetUrlSignature | None,
    ) -> None:
        self.target_url: str = target_url
        self.signature: TargetUrlSignature | None = signature

    @staticmethod
    def from_dva_target_url(header: str) -> DvaTarget:
        separator = f"?{TARGET_URL_SIGNATURE_QUERY_PARAM}="

        if separator in header:
            target_url, signature = header.split(separator)
        else:
            target_url = header
            signature = None

        return DvaTarget(
            target_url=target_url,
            signature=TargetUrlSignature(signature) if signature else None,
        )
