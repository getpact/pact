"""SD-JWT compact form helpers (RFC 9901).

Pure parsing and base64url utilities. No verification logic lives here so the
parser can be reused outside the main verify path (debugging, audit tooling).
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ParsedCompact:
    issuer_jws: str
    disclosures: tuple[str, ...]
    kb_jwt: str | None
    sd_hash_input: str


def b64url_decode(s: str) -> bytes:
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def sha256_b64url(data: bytes) -> str:
    return b64url_encode(hashlib.sha256(data).digest())


def parse_compact(compact: str) -> ParsedCompact | None:
    if not isinstance(compact, str) or len(compact) == 0:
        return None
    parts = compact.split("~")
    if len(parts) < 2:
        return None
    issuer_jws = parts[0]
    if not issuer_jws or issuer_jws.count(".") != 2:
        return None
    last = parts[-1]
    kb_jwt: str | None = None
    if last == "":
        end_idx = len(parts) - 1
    else:
        if last.count(".") != 2:
            return None
        kb_jwt = last
        end_idx = len(parts) - 1
    disclosures = tuple(p for p in parts[1:end_idx] if len(p) > 0)
    sd_hash_input = compact[: len(compact) - len(kb_jwt)] if kb_jwt else compact
    return ParsedCompact(
        issuer_jws=issuer_jws,
        disclosures=disclosures,
        kb_jwt=kb_jwt,
        sd_hash_input=sd_hash_input,
    )


def decode_json_segment(seg: str) -> Any:
    return json.loads(b64url_decode(seg).decode("utf-8"))


def decode_jws_payload(jws: str) -> dict[str, Any] | None:
    parts = jws.split(".")
    if len(parts) != 3:
        return None
    try:
        decoded = decode_json_segment(parts[1])
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    return decoded


def decode_jws_header(jws: str) -> dict[str, Any] | None:
    parts = jws.split(".")
    if len(parts) != 3:
        return None
    try:
        decoded = decode_json_segment(parts[0])
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    return decoded


def collect_disclosed(disclosures: tuple[str, ...]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for tok in disclosures:
        try:
            arr = json.loads(b64url_decode(tok).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(arr, list) or len(arr) != 3:
            continue
        name = arr[1]
        if not isinstance(name, str):
            continue
        out[name] = arr[2]
    return out
