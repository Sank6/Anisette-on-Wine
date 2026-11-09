from __future__ import annotations

import base64
import hashlib
import hmac


class TokenError(ValueError):
    pass


def decode_identifier(value: object) -> bytes:
    if not isinstance(value, str) or len(value) > 1024:
        raise TokenError("identifier must be base64 text")
    try:
        identifier = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise TokenError("identifier is not valid base64") from exc
    if not 16 <= len(identifier) <= 64:
        raise TokenError("identifier must decode to 16-64 bytes")
    return identifier


class ProvisioningTokens:
    VERSION = b"\x01"

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("token key must be 32 bytes")
        self._key = key

    def issue(self, identifier: bytes) -> str:
        body = self.VERSION + hashlib.sha256(identifier).digest()
        signature = hmac.digest(self._key, body, "sha256")
        return base64.b64encode(body + signature).decode("ascii")

    def verify(self, identifier: bytes, encoded: object) -> None:
        if not isinstance(encoded, str) or len(encoded) > 1024:
            raise TokenError("adi_pb must be base64 text")
        try:
            token = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise TokenError("adi_pb is not valid base64") from exc
        if len(token) != 65 or token[:1] != self.VERSION:
            raise TokenError("adi_pb has an unsupported format")
        body, signature = token[:33], token[33:]
        expected_body = self.VERSION + hashlib.sha256(identifier).digest()
        expected_signature = hmac.digest(self._key, expected_body, "sha256")
        if not hmac.compare_digest(body, expected_body) or not hmac.compare_digest(
            signature, expected_signature
        ):
            raise TokenError("adi_pb does not belong to this identifier")
