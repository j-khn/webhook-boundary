from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import hashlib
import hmac
import re
import time


class SignatureError(ValueError):
    pass


class MalformedSignature(SignatureError):
    pass


class ExpiredSignature(SignatureError):
    pass


@dataclass(frozen=True)
class VerifiedWebhook:
    timestamp: int
    version: str = "v1"


def sign_for_example(secret: bytes, raw_body: bytes, timestamp: int) -> str:
    if not secret:
        raise ValueError("secret must not be empty")
    message = str(timestamp).encode("ascii") + b"." + raw_body
    digest = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


def verify_signature(
    raw_body: bytes,
    signature_headers: str | Sequence[str],
    secrets: Sequence[bytes],
    *,
    now: int | None = None,
    tolerance_seconds: int = 300,
) -> VerifiedWebhook:
    if not isinstance(raw_body, bytes):
        raise TypeError("raw_body must be the exact request bytes")
    if tolerance_seconds < 0:
        raise ValueError("tolerance_seconds must be non-negative")
    if not secrets or any(not isinstance(secret, bytes) or not secret for secret in secrets):
        raise ValueError("provide at least one non-empty bytes secret")

    fields = [signature_headers] if isinstance(signature_headers, str) else list(signature_headers)
    if not fields or any(not isinstance(field, str) for field in fields):
        raise MalformedSignature("signature header is missing or invalid")

    timestamps: list[int] = []
    signatures: list[str] = []
    for field in fields:
        if len(field) > 8192:
            raise MalformedSignature("signature header is too large")
        for item in field.split(","):
            name, separator, value = item.strip().partition("=")
            if not separator:
                raise MalformedSignature("malformed signature field")
            if name == "t":
                if len(value) > 19 or not value.isascii() or not value.isdigit():
                    raise MalformedSignature("timestamp must be decimal Unix seconds")
                timestamps.append(int(value))
            elif name == "v1":
                candidate = value.lower()
                if not re.fullmatch(r"[0-9a-f]{64}", candidate):
                    raise MalformedSignature("v1 signature must be a 32-byte hex digest")
                signatures.append(candidate)

    if len(timestamps) != 1 or not signatures:
        raise MalformedSignature("expected one timestamp and at least one v1 signature")

    timestamp = timestamps[0]
    current_time = int(time.time()) if now is None else now
    if abs(current_time - timestamp) > tolerance_seconds:
        raise ExpiredSignature("signature timestamp is outside the allowed window")

    message = str(timestamp).encode("ascii") + b"." + raw_body
    expected = [
        hmac.new(secret, message, hashlib.sha256).hexdigest()
        for secret in secrets
    ]
    matched = False
    for candidate in signatures:
        for digest in expected:
            matched = hmac.compare_digest(candidate, digest) or matched

    if not matched:
        raise SignatureError("no signature matched an active secret")
    return VerifiedWebhook(timestamp=timestamp)
