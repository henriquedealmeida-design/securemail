from __future__ import annotations

import hashlib
import os
import re
from urllib.parse import quote

DEFAULT_DOMAIN = (
    os.environ.get("SECUREMAIL_DOMAIN", "securemail.local").strip()
    or "securemail.local"
)

_LOCAL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._%+\-]{0,62}[a-z0-9])?$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$"
)
_ADDRESS_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def normalize_address(value: str, default_domain: str = DEFAULT_DOMAIN) -> str:
    address = value.strip().lower()
    domain = default_domain.strip().lower()
    if not address:
        raise ValueError("email address required")
    if "@" not in address:
        address = f"{address}@{domain}"
    local, sep, host = address.partition("@")
    if not sep or "@" in host:
        raise ValueError("invalid email address")
    if not _LOCAL_RE.fullmatch(local):
        raise ValueError("invalid email local part")
    if not _DOMAIN_RE.fullmatch(host):
        raise ValueError("invalid email domain")
    return f"{local}@{host}"


def identity_filename(address: str) -> str:
    return f"{quote(address, safe='')}.json"


def address_id(address: str, default_domain: str = DEFAULT_DOMAIN) -> str:
    normalized = normalize_address(address, default_domain)
    return hashlib.sha256(f"securemail-address-v1|{normalized}".encode("utf-8")).hexdigest()


def is_address_id(value: str) -> bool:
    return bool(_ADDRESS_ID_RE.fullmatch(value))
