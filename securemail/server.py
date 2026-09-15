"""Storage server — deliberately blind.

The server keeps exactly two things:
  1. a directory of usernames -> public keys
  2. a queue of opaque encrypted envelopes per recipient

It has no private keys, no plaintext, no message metadata beyond sender name
and arrival time. Built on the Python standard library + cryptography.

Security model (post-audit hardening):
- /inbox and /ack require a request signature: the client signs
  "{username}|{unix_timestamp}" with its Ed25519 key; the server verifies
  against the registered public key. A 60-second window blocks replays.
- /send requires the same signature from the declared sender — nobody can
  queue envelopes under someone else's name.
- Request bodies are capped (64 KB) and per-IP rate limited.

API:
  POST /register      {"username", "signing_pub", "encryption_pub"}
  GET  /keys/<user>   -> {"username", "signing_pub", "encryption_pub"}   (public)
  POST /send          {"recipient", "envelope": {...}}   + auth headers
  GET  /inbox/<user>  -> [{"id", "sender", "envelope", "received_at"}]   + auth
  POST /ack           {"username", "ids": [...]}                          + auth

Auth headers: X-Timestamp (unix seconds), X-Signature (base64 Ed25519).
"""

from __future__ import annotations

import base64
import json
import logging
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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
    username       TEXT PRIMARY KEY,
    signing_pub    TEXT NOT NULL,
    encryption_pub TEXT NOT NULL,
    registered_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient   TEXT NOT NULL,
    sender      TEXT NOT NULL,
    envelope    TEXT NOT NULL,   -- JSON, opaque to us
    received_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient);
"""

# per-IP sliding-window rate limiter
_buckets: dict[str, list[float]] = {}


class Store:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def register(self, username: str, signing_pub: str, encryption_pub: str) -> bool:
        try:
            self.conn.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?)",
                (username, signing_pub, encryption_pub, time.time()),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_keys(self, username: str) -> dict | None:
        row = self.conn.execute(
            "SELECT username, signing_pub, encryption_pub FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None

    def get_signing_key(self, username: str) -> str | None:
        row = self.conn.execute(
            "SELECT signing_pub FROM users WHERE username = ?", (username,)
        ).fetchone()
        return str(row["signing_pub"]) if row else None

    def store_message(self, recipient: str, sender: str, envelope: dict) -> None:
        self.conn.execute(
            "INSERT INTO messages (recipient, sender, envelope, received_at)"
            " VALUES (?, ?, ?, ?)",
            (recipient, sender, json.dumps(envelope), time.time()),
        )
        self.conn.commit()

    def inbox(self, username: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, sender, envelope, received_at FROM messages"
            " WHERE recipient = ? ORDER BY id",
            (username,),
        ).fetchall()
        return [
            {
                "id": r["id"],
                "sender": r["sender"],
                "envelope": json.loads(r["envelope"]),
                "received_at": r["received_at"],
            }
            for r in rows
        ]

    def ack(self, username: str, ids: list[int]) -> None:
        self.conn.executemany(
            "DELETE FROM messages WHERE id = ? AND recipient = ?",
            [(i, username) for i in ids],
        )
        self.conn.commit()


def verify_requester(store: Store, username: str, headers) -> bool:
    """Verify an Ed25519 request signature over "{username}|{timestamp}".

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
        pub_b64 = store.get_signing_key(username)
        if pub_b64 is None:
            return False
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pub.verify(base64.b64decode(sig_b64), f"{username}|{ts}".encode())
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
                    ok = store.register(
                        body["username"], body["signing_pub"], body["encryption_pub"]
                    )
                    audit.info("register user=%s ok=%s ip=%s",
                               body["username"], ok, self.client_address[0])
                    self._reply(201 if ok else 409, {"registered": ok})
                elif self.path == "/send":
                    env = body["envelope"]
                    if store.get_keys(env["sender"]) is None:
                        self._reply(403, {"error": "unregistered sender"})
                        return
                    if not verify_requester(store, env["sender"], self.headers):
                        self._reply(403, {"error": "sender signature required"})
                        return
                    if store.get_keys(body["recipient"]) is None:
                        self._reply(404, {"error": "unknown recipient"})
                        return
                    store.store_message(body["recipient"], env["sender"], env)
                    audit.info("send sender=%s recipient=%s ip=%s",
                               env["sender"], body["recipient"],
                               self.client_address[0])
                    self._reply(202, {"queued": True})
                elif self.path == "/ack":
                    if not verify_requester(store, body["username"], self.headers):
                        self._reply(403, {"error": "signature required"})
                        return
                    store.ack(body["username"], body.get("ids", []))
                    audit.info("ack user=%s n=%d ip=%s", body["username"],
                               len(body.get("ids", [])), self.client_address[0])
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
            if self.path.startswith("/keys/"):
                username = self.path.removeprefix("/keys/")
                keys = store.get_keys(username)
                if keys is None:
                    self._reply(404, {"error": "unknown user"})
                else:
                    self._reply(200, keys)
            elif self.path.startswith("/inbox/"):
                username = self.path.removeprefix("/inbox/")
                if not verify_requester(store, username, self.headers):
                    audit.info("inbox-denied user=%s ip=%s",
                               username, self.client_address[0])
                    self._reply(403, {"error": "signature required"})
                    return
                self._reply(200, store.inbox(username))
            else:
                self._reply(404, {"error": "not found"})

    return Handler


def run(host: str = "127.0.0.1", port: int = 8471, db_path: str = "securemail.db"):
    store = Store(db_path)
    server = ThreadingHTTPServer((host, port), make_handler(store))
    print(f"securemail server listening on http://{host}:{port} (db: {db_path})")
    print("the server stores public keys and encrypted envelopes only.")
    print("inbox/ack/send require an request signature.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")


if __name__ == "__main__":
    run()
