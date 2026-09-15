"""Command-line client.

Identity files live in ~/.securemail/<username>.json with 0600 permissions.

Usage:
    python -m securemail.client register alice
    python -m securemail.client send alice bob "meet at 18:00, usual place"
    python -m securemail.client inbox bob

Authenticated endpoints (/send, /inbox, /ack) carry two headers:
    X-Timestamp: unix seconds
    X-Signature: base64 Ed25519 signature over "{username}|{timestamp}"
The server verifies them against the registered public key.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

from .addressing import DEFAULT_DOMAIN, identity_filename, normalize_address
from .crypto import Identity, decrypt_message, encrypt_message

DEFAULT_SERVER = "http://127.0.0.1:8471"
IDENTITY_DIR = Path.home() / ".securemail"


def _request(
    method: str,
    url: str,
    payload: dict | None = None,
    headers: dict | None = None,
) -> dict | list:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise SystemExit(f"server error {exc.code}: {detail}")
    except urllib.error.URLError:
        raise SystemExit(f"cannot reach server at {url} — is it running?")


def _auth_headers(identity: Identity, username: str) -> dict:
    """Sign "{username}|{timestamp}" — proves key possession to the server."""
    ts = str(int(time.time()))
    sig = identity.signing_key.sign(f"{username}|{ts}".encode())
    return {"X-Timestamp": ts, "X-Signature": base64.b64encode(sig).decode()}


def _normalize_cli_address(address: str, default_domain: str) -> str:
    try:
        return normalize_address(address, default_domain)
    except ValueError as exc:
        raise SystemExit(str(exc))


def _identity_path(address: str) -> Path:
    return IDENTITY_DIR / identity_filename(address)


def _load_identity(address: str) -> Identity:
    path = _identity_path(address)
    if not path.exists():
        raise SystemExit(f"no identity for '{address}' — run: register {address}")
    return Identity.load(str(path))


def cmd_register(args) -> int:
    username = _normalize_cli_address(args.username, args.domain)
    path = _identity_path(username)
    if path.exists():
        print(f"identity already exists: {path}")
        return 1
    IDENTITY_DIR.mkdir(parents=True, exist_ok=True)
    identity = Identity.generate()
    identity.save(str(path))
    result = _request(
        "POST", f"{args.server}/register",
        {
            "username": username,
            "signing_pub": identity.public_signing_b64(),
            "encryption_pub": identity.public_encryption_b64(),
        },
    )
    if result.get("registered"):
        print(f"registered '{username}' — identity stored in {path} (mode 0600)")
        return 0
    print(f"username '{username}' is already taken on this server")
    return 1


def cmd_send(args) -> int:
    sender = _normalize_cli_address(args.sender, args.domain)
    recipient = _normalize_cli_address(args.recipient, args.domain)
    identity = _load_identity(sender)
    keys = _request("GET", f"{args.server}/keys/{quote(recipient, safe='')}")
    envelope = encrypt_message(
        identity, sender, recipient, keys["encryption_pub"], args.message
    )
    _request(
        "POST", f"{args.server}/send",
        {"recipient": recipient, "envelope": envelope},
        headers=_auth_headers(identity, sender),
    )
    print(f"message encrypted and queued for '{recipient}'")
    print("the server only sees an opaque envelope — not a single word of content.")
    return 0


def cmd_inbox(args) -> int:
    username = _normalize_cli_address(args.username, args.domain)
    identity = _load_identity(username)
    messages = _request(
        "GET", f"{args.server}/inbox/{quote(username, safe='')}",
        headers=_auth_headers(identity, username),
    )
    if not messages:
        print("inbox empty")
        return 0
    read_ids = []
    for msg in messages:
        keys = _request("GET", f"{args.server}/keys/{quote(msg['sender'], safe='')}")
        try:
            text = decrypt_message(
                identity, username, keys["signing_pub"], msg["envelope"]
            )
        except Exception:
            print(f"  [!] message #{msg['id']} from {msg['sender']}: "
                  f"signature/decryption FAILED — possible tampering, skipped")
            continue
        when = dt.datetime.fromtimestamp(msg["received_at"]).strftime("%Y-%m-%d %H:%M")
        print(f"  [{when}] {msg['sender']}: {text}")
        read_ids.append(msg["id"])
    if read_ids and not args.keep:
        _request("POST", f"{args.server}/ack",
                 {"username": username, "ids": read_ids},
                 headers=_auth_headers(identity, username))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="securemail",
        description="End-to-end encrypted messaging — the server never sees plaintext",
    )
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--domain", default=DEFAULT_DOMAIN,
                        help="default domain appended when an address has no @")
    sub = parser.add_subparsers(dest="command", required=True)

    p_reg = sub.add_parser("register", help="create an identity and publish public keys")
    p_reg.add_argument("username")
    p_reg.set_defaults(func=cmd_register)

    p_send = sub.add_parser("send", help="encrypt and queue a message")
    p_send.add_argument("sender")
    p_send.add_argument("recipient")
    p_send.add_argument("message")
    p_send.set_defaults(func=cmd_send)

    p_in = sub.add_parser("inbox", help="fetch, verify and decrypt your messages")
    p_in.add_argument("username")
    p_in.add_argument("--keep", action="store_true", help="don't delete after reading")
    p_in.set_defaults(func=cmd_inbox)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
