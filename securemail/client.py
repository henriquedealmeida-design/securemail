"""Command-line client.

Identity files live in ~/.securemail/<address>.json with 0600 permissions.

Usage:
    python -m securemail.client register henrique.de.almeida@securemail.local
    python -m securemail.client send henrique.de.almeida@securemail.local contact@securemail.local "meet at 18:00, usual place"
    python -m securemail.client inbox contact@securemail.local

Authenticated endpoints (/send, /inbox, /ack) carry two headers:
    X-Timestamp: unix seconds
    X-Signature: base64 Ed25519 signature over "{address_id}|{timestamp}"
The server verifies them against the registered public key.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import html
import json
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote

from .addressing import (DEFAULT_DOMAIN, address_id, identity_filename,
                         normalize_address)
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


def _auth_headers(identity: Identity, address_id_value: str) -> dict:
    """Sign "{address_id}|{timestamp}" — proves key possession to the server."""
    ts = str(int(time.time()))
    sig = identity.signing_key.sign(f"{address_id_value}|{ts}".encode())
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


def _lookup_keys(server: str, address_id_value: str) -> dict:
    return _request("GET", f"{server}/keys/{quote(address_id_value, safe='')}")


def _send_encrypted_message(
    server: str,
    identity: Identity,
    sender: str,
    recipient: str,
    default_domain: str,
    message: str,
) -> str:
    sender_id = address_id(sender, default_domain)
    recipient_id = address_id(recipient, default_domain)
    keys = _lookup_keys(server, recipient_id)
    envelope = encrypt_message(
        identity, sender, sender_id, recipient_id, keys["encryption_pub"], message
    )
    _request(
        "POST", f"{server}/send",
        {"recipient_id": recipient_id, "envelope": envelope},
        headers=_auth_headers(identity, sender_id),
    )
    return recipient


def _fetch_inbox(
    server: str,
    identity: Identity,
    username: str,
    keep: bool = True,
) -> list[dict]:
    user_id = address_id(username)
    messages = _request(
        "GET", f"{server}/inbox/{quote(user_id, safe='')}",
        headers=_auth_headers(identity, user_id),
    )
    inbox = []
    read_ids = []
    for msg in messages:
        keys = _lookup_keys(server, msg["sender_id"])
        try:
            payload = decrypt_message(
                identity, user_id, keys["signing_pub"], msg["envelope"], username
            )
        except Exception:
            inbox.append(
                {
                    "id": msg["id"],
                    "received_at": msg["received_at"],
                    "sender": "unknown",
                    "message": "signature/decryption FAILED — possible tampering",
                    "ok": False,
                }
            )
            continue
        inbox.append(
            {
                "id": msg["id"],
                "received_at": msg["received_at"],
                "sender": payload["sender"],
                "message": payload["message"],
                "ok": True,
            }
        )
        read_ids.append(msg["id"])
    if read_ids and not keep:
        _request(
            "POST", f"{server}/ack",
            {"address_id": user_id, "ids": read_ids},
            headers=_auth_headers(identity, user_id),
        )
    return inbox


def _ack_messages(server: str, identity: Identity, username: str, ids: list[int]) -> None:
    user_id = address_id(username)
    _request(
        "POST", f"{server}/ack",
        {"address_id": user_id, "ids": ids},
        headers=_auth_headers(identity, user_id),
    )


def _render_mailbox_page(username: str, messages: list[dict], notice: str = "") -> str:
    notice_html = (
        f"<p class='notice'>{html.escape(notice)}</p>" if notice else ""
    )
    items = []
    for msg in messages:
        when = dt.datetime.fromtimestamp(msg["received_at"]).strftime("%Y-%m-%d %H:%M")
        sender = html.escape(msg["sender"])
        body = html.escape(msg["message"]).replace("\n", "<br>")
        status = "ok" if msg["ok"] else "error"
        checkbox = (
            f"<label><input type='checkbox' name='ids' value='{msg['id']}' checked> Supprimer</label>"
            if msg["ok"] else ""
        )
        items.append(
            "<li class='message'>"
            f"<div><strong>{sender}</strong> <span class='meta'>#{msg['id']} · {when}</span></div>"
            f"<p class='{status}'>{body}</p>"
            f"{checkbox}"
            "</li>"
        )
    inbox_html = "".join(items) or "<li class='message empty'>Aucun message</li>"
    safe_user = html.escape(username)
    return f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>securemail privé</title>
  <style>
    body {{ font-family: sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; background: #0f172a; color: #e2e8f0; }}
    .panel {{ background: #111827; border: 1px solid #334155; border-radius: 12px; padding: 1rem; margin-bottom: 1rem; }}
    input, textarea, button {{ width: 100%; box-sizing: border-box; margin-top: .5rem; padding: .75rem; border-radius: 8px; border: 1px solid #475569; background: #020617; color: #e2e8f0; }}
    button {{ cursor: pointer; background: #1d4ed8; border: none; }}
    .secondary {{ background: #334155; }}
    .message {{ list-style: none; margin: 0 0 1rem; padding: 1rem; background: #020617; border-radius: 10px; }}
    .meta {{ color: #94a3b8; font-size: .9rem; }}
    .ok {{ color: #e2e8f0; }}
    .error {{ color: #fca5a5; }}
    .notice {{ color: #93c5fd; }}
    .empty {{ color: #94a3b8; }}
    ul {{ padding: 0; }}
  </style>
</head>
<body>
  <h1>Boîte privée de {safe_user}</h1>
  {notice_html}
  <section class="panel">
    <h2>Envoyer un message</h2>
    <form method="post" action="/send">
      <label>Destinataire<input type="text" name="recipient" required placeholder="contact@securemail.local"></label>
      <label>Message<textarea name="message" rows="6" required></textarea></label>
      <button type="submit">Envoyer</button>
    </form>
  </section>
  <section class="panel">
    <h2>Réception</h2>
    <form method="post" action="/ack">
      <ul>{inbox_html}</ul>
      <button class="secondary" type="submit">Supprimer les messages cochés</button>
    </form>
  </section>
  <form method="get" action="/">
    <button class="secondary" type="submit">Actualiser</button>
  </form>
</body>
</html>"""


def _mailbox_handler(server: str, username: str, identity: Identity, default_domain: str):
    class MailboxHandler(BaseHTTPRequestHandler):
        def _reply_html(self, body: str, status: int = 200) -> None:
            raw = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _redirect(self, location: str = "/") -> None:
            self.send_response(303)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def _form(self) -> dict[str, list[str]]:
            length = int(self.headers.get("Content-Length", "0"))
            data = self.rfile.read(length).decode("utf-8")
            return parse_qs(data, keep_blank_values=True)

        def do_GET(self):
            notice = parse_qs(self.path.partition("?")[2]).get("notice", [""])[0]
            try:
                messages = _fetch_inbox(server, identity, username, keep=True)
                self._reply_html(_render_mailbox_page(username, messages, notice))
            except SystemExit as exc:
                self._reply_html(_render_mailbox_page(username, [], str(exc)), status=502)

        def do_POST(self):
            try:
                if self.path == "/send":
                    form = self._form()
                    recipient = _normalize_cli_address(form.get("recipient", [""])[0], default_domain)
                    message = form.get("message", [""])[0].strip()
                    if not message:
                        raise SystemExit("message required")
                    _send_encrypted_message(server, identity, username, recipient, default_domain, message)
                    self._redirect("/?notice=Message%20envoy%C3%A9")
                elif self.path == "/ack":
                    form = self._form()
                    ids = [int(value) for value in form.get("ids", [])]
                    if ids:
                        _ack_messages(server, identity, username, ids)
                    self._redirect("/?notice=Bo%C3%AEte%20mise%20%C3%A0%20jour")
                else:
                    self.send_error(404)
            except (SystemExit, ValueError) as exc:
                messages = _fetch_inbox(server, identity, username, keep=True)
                self._reply_html(_render_mailbox_page(username, messages, str(exc)), status=400)

        def log_message(self, fmt, *args):
            return

    return MailboxHandler


def cmd_register(args) -> int:
    username = _normalize_cli_address(args.username, args.domain)
    user_id = address_id(username, args.domain)
    path = _identity_path(username)
    if path.exists():
        print(f"identity already exists: {path}")
        return 1
    identity = Identity.generate()
    result = _request(
        "POST", f"{args.server}/register",
        {
            "address_id": user_id,
            "signing_pub": identity.public_signing_b64(),
            "encryption_pub": identity.public_encryption_b64(),
        },
    )
    if result.get("registered"):
        IDENTITY_DIR.mkdir(parents=True, exist_ok=True)
        identity.save(str(path))
        print(f"registered '{username}' — identity stored in {path} (mode 0600)")
        return 0
    print(f"username '{username}' is already taken on this server")
    return 1


def cmd_send(args) -> int:
    sender = _normalize_cli_address(args.sender, args.domain)
    recipient = _normalize_cli_address(args.recipient, args.domain)
    identity = _load_identity(sender)
    queued_for = _send_encrypted_message(
        args.server, identity, sender, recipient, args.domain, args.message
    )
    print(f"message encrypted and queued for '{queued_for}'")
    print("the server only sees an opaque envelope — not a single word of content.")
    return 0


def cmd_inbox(args) -> int:
    username = _normalize_cli_address(args.username, args.domain)
    identity = _load_identity(username)
    messages = _fetch_inbox(args.server, identity, username, keep=args.keep)
    if not messages:
        print("inbox empty")
        return 0
    for msg in messages:
        when = dt.datetime.fromtimestamp(msg["received_at"]).strftime("%Y-%m-%d %H:%M")
        if msg["ok"]:
            print(f"  [{when}] {msg['sender']}: {msg['message']}")
        else:
            print(f"  [!] message #{msg['id']} ({when}): {msg['message']}, skipped")
    if not args.keep:
        ok_ids = [msg["id"] for msg in messages if msg["ok"]]
        if ok_ids:
            _ack_messages(args.server, identity, username, ok_ids)
    return 0


def cmd_mailbox(args) -> int:
    username = _normalize_cli_address(args.username, args.domain)
    identity = _load_identity(username)
    server = ThreadingHTTPServer(
        (args.host, args.port),
        _mailbox_handler(args.server, username, identity, args.domain),
    )
    print(f"private mailbox available on http://{args.host}:{args.port} for {username}")
    print("this interface is local-only and keeps clear-text mail on your machine.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down mailbox")
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

    p_box = sub.add_parser("mailbox", help="start a private local web mailbox")
    p_box.add_argument("username")
    p_box.add_argument("--host", default="127.0.0.1")
    p_box.add_argument("--port", type=int, default=8480)
    p_box.set_defaults(func=cmd_mailbox)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
