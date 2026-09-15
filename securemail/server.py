"""Storage server — deliberately blind.

The server keeps exactly two things:
  1. a directory of opaque address identifiers -> public keys
  2. a queue of opaque encrypted envelopes per recipient identifier

It has no private keys, no plaintext, and no clear-text email addresses. Built
on the Python standard library + cryptography.

Security model (post-audit hardening):
- /inbox and /ack require a request signature: the client signs
  "{address_id}|{unix_timestamp}" with its Ed25519 key; the server verifies
  against the registered public key. A 60-second window blocks replays.
- /send requires the same signature from the declared sender — nobody can
  queue envelopes under someone else's name.
- Request bodies are capped (64 KB) and per-IP rate limited.

API:
  POST /register      {"address_id", "signing_pub", "encryption_pub"}
  GET  /keys/<id>     -> {"address_id", "signing_pub", "encryption_pub"}  (public)
  POST /send          {"recipient_id", "envelope": {...}}                 + auth headers
  GET  /inbox/<id>    -> [{"id", "sender_id", "envelope", "received_at"}] + auth
  POST /ack           {"address_id", "ids": [...]}                        + auth

Auth headers: X-Timestamp (unix seconds), X-Signature (base64 Ed25519).
"""

from __future__ import annotations

import base64
import json
import logging
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .addressing import address_id, is_address_id, normalize_address
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_BODY = 64 * 1024          # 64 KB is ample for an envelope
RATE_LIMIT = 30               # requests per minute per IP
AUTH_WINDOW = 60              # seconds of tolerance on X-Timestamp

logging.basicConfig(
    filename="securemail-audit.log",
    level=logging.INFO,
    format="%(asctime)s %(message)s",
)
audit = logging.getLogger("audit")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    address_id     TEXT PRIMARY KEY,
    signing_pub    TEXT NOT NULL,
    encryption_pub TEXT NOT NULL,
    registered_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id TEXT NOT NULL,
    sender_id    TEXT NOT NULL,
    envelope    TEXT NOT NULL,   -- JSON, opaque to us
    received_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);
"""

# per-IP sliding-window rate limiter
_buckets: dict[str, list[float]] = {}


class Store:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._migrate_legacy_schema()
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def _table_columns(self, table: str) -> list[str]:
        return [
            str(row["name"])
            for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()
        ]

    def _migrate_legacy_schema(self) -> None:
        user_columns = self._table_columns("users")
        message_columns = self._table_columns("messages")
        legacy_users = "username" in user_columns and "address_id" not in user_columns
        legacy_messages = "recipient" in message_columns and "recipient_id" not in message_columns
        if not legacy_users and not legacy_messages:
            return
        if legacy_users:
            self.conn.execute("ALTER TABLE users RENAME TO users_legacy")
        if legacy_messages:
            self.conn.execute("ALTER TABLE messages RENAME TO messages_legacy")
        self.conn.executescript(SCHEMA)
        if legacy_users:
            rows = self.conn.execute(
                "SELECT username, signing_pub, encryption_pub, registered_at FROM users_legacy"
            ).fetchall()
            for row in rows:
                migrated_id = address_id(normalize_address(str(row["username"])))
                self.conn.execute(
                    "INSERT OR IGNORE INTO users (address_id, signing_pub, encryption_pub, registered_at)"
                    " VALUES (?, ?, ?, ?)",
                    (
                        migrated_id,
                        row["signing_pub"],
                        row["encryption_pub"],
                        row["registered_at"],
                    ),
                )
            self.conn.execute("DROP TABLE users_legacy")
        if legacy_messages:
            rows = self.conn.execute(
                "SELECT id, recipient, sender, envelope, received_at FROM messages_legacy"
            ).fetchall()
            for row in rows:
                recipient_address = normalize_address(str(row["recipient"]))
                sender_address = normalize_address(str(row["sender"]))
                envelope = json.loads(row["envelope"])
                if "sender" in envelope:
                    envelope["sender"] = normalize_address(str(envelope["sender"]))
                self.conn.execute(
                    "INSERT INTO messages (id, recipient_id, sender_id, envelope, received_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        row["id"],
                        address_id(recipient_address),
                        address_id(sender_address),
                        json.dumps(envelope),
                        row["received_at"],
                    ),
                )
            self.conn.execute("DROP TABLE messages_legacy")
        self.conn.commit()

    def register(self, address_id: str, signing_pub: str, encryption_pub: str) -> bool:
        try:
            self.conn.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?)",
                (address_id, signing_pub, encryption_pub, time.time()),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_keys(self, address_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT address_id, signing_pub, encryption_pub FROM users WHERE address_id = ?",
            (address_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_signing_key(self, address_id: str) -> str | None:
        row = self.conn.execute(
            "SELECT signing_pub FROM users WHERE address_id = ?", (address_id,)
        ).fetchone()
        return str(row["signing_pub"]) if row else None

    def store_message(self, recipient_id: str, sender_id: str, envelope: dict) -> None:
        self.conn.execute(
            "INSERT INTO messages (recipient_id, sender_id, envelope, received_at)"
            " VALUES (?, ?, ?, ?)",
            (recipient_id, sender_id, json.dumps(envelope), time.time()),
        )
        self.conn.commit()

    def inbox(self, address_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, sender_id, envelope, received_at FROM messages"
            " WHERE recipient_id = ? ORDER BY id",
            (address_id,),
        ).fetchall()
        return [
            {
                "id": r["id"],
                "sender_id": r["sender_id"],
                "envelope": json.loads(r["envelope"]),
                "received_at": r["received_at"],
            }
            for r in rows
        ]

    def ack(self, address_id: str, ids: list[int]) -> None:
        self.conn.executemany(
            "DELETE FROM messages WHERE id = ? AND recipient_id = ?",
            [(i, address_id) for i in ids],
        )
        self.conn.commit()


def verify_requester(store: Store, address_id: str, headers) -> bool:
    """Verify an Ed25519 request signature over "{address_id}|{timestamp}".

    The registered public signing key authenticates the request; the
    timestamp window (60 s) blocks replay of captured requests.
    """
    sig_b64 = headers.get("X-Signature")
    ts = headers.get("X-Timestamp")
    if not sig_b64 or not ts:
        return False
    try:
        if abs(time.time() - float(ts)) > AUTH_WINDOW:
            return False
        pub_b64 = store.get_signing_key(address_id)
        if pub_b64 is None:
            return False
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pub.verify(base64.b64decode(sig_b64), f"{address_id}|{ts}".encode())
        return True
    except Exception:
        return False


def make_handler(store: Store):
    class Handler(BaseHTTPRequestHandler):
        def _rate_ok(self) -> bool:
            now = time.time()
            ip = self.client_address[0]
            hits = [t for t in _buckets.get(ip, []) if now - t < 60]
            if len(hits) >= RATE_LIMIT:
                return False
            hits.append(now)
            _buckets[ip] = hits
            return True

        def _json_body(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY:
                raise ValueError("body too large")
            return json.loads(self.rfile.read(length) or b"{}")

        def _address_id(self, value: str) -> str:
            if not is_address_id(value):
                raise ValueError("invalid address identifier")
            return value

        def _reply(self, code: int, payload: dict | list) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):  # access logs go to the audit log
            audit.info("access " + fmt, *args)

        def do_POST(self):
            if not self._rate_ok():
                self._reply(429, {"error": "rate limit exceeded"})
                return
            try:
                body = self._json_body()
                if self.path == "/register":
                    address_id = self._address_id(body["address_id"])
                    ok = store.register(
                        address_id, body["signing_pub"], body["encryption_pub"]
                    )
                    audit.info("register ok=%s ip=%s", ok, self.client_address[0])
                    self._reply(201 if ok else 409, {"registered": ok})
                elif self.path == "/send":
                    env = body["envelope"]
                    sender_id = self._address_id(env["sender_id"])
                    recipient_id = self._address_id(body["recipient_id"])
                    env["sender_id"] = sender_id
                    if store.get_keys(sender_id) is None:
                        self._reply(403, {"error": "unregistered sender"})
                        return
                    if not verify_requester(store, sender_id, self.headers):
                        self._reply(403, {"error": "sender signature required"})
                        return
                    if store.get_keys(recipient_id) is None:
                        self._reply(404, {"error": "unknown recipient"})
                        return
                    store.store_message(recipient_id, sender_id, env)
                    audit.info("send queued ip=%s", self.client_address[0])
                    self._reply(202, {"queued": True})
                elif self.path == "/ack":
                    address_id = self._address_id(body["address_id"])
                    if not verify_requester(store, address_id, self.headers):
                        self._reply(403, {"error": "signature required"})
                        return
                    store.ack(address_id, body.get("ids", []))
                    audit.info("ack n=%d ip=%s", len(body.get("ids", [])),
                               self.client_address[0])
                    self._reply(200, {"acked": True})
                else:
                    self._reply(404, {"error": "not found"})
            except ValueError as exc:
                self._reply(400, {"error": str(exc)})
            except (KeyError, json.JSONDecodeError) as exc:
                self._reply(400, {"error": f"bad request: {exc}"})

        def do_GET(self):
            if not self._rate_ok():
                self._reply(429, {"error": "rate limit exceeded"})
                return
            path = urlparse(self.path).path
            if path.startswith("/keys/"):
                address_id = self._address_id(path.removeprefix("/keys/"))
                keys = store.get_keys(address_id)
                if keys is None:
                    self._reply(404, {"error": "unknown user"})
                else:
                    self._reply(200, keys)
            elif path.startswith("/inbox/"):
                address_id = self._address_id(path.removeprefix("/inbox/"))
                if not verify_requester(store, address_id, self.headers):
                    audit.info("inbox-denied ip=%s", self.client_address[0])
                    self._reply(403, {"error": "signature required"})
                    return
                self._reply(200, store.inbox(address_id))
            else:
                self._reply(404, {"error": "not found"})

    return Handler


def run(host: str = "127.0.0.1", port: int = 8471, db_path: str = "securemail.db"):
    store = Store(db_path)
    server = ThreadingHTTPServer((host, port), make_handler(store))
    print(f"securemail server listening on http://{host}:{port} (db: {db_path})")
    print("the server stores only opaque address identifiers and encrypted envelopes.")
    print("inbox/ack/send require a signed request.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")


if __name__ == "__main__":
    run()
