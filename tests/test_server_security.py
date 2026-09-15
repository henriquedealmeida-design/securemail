"""Security tests for the hardened server: request signatures, body cap,
rate limiting. These exercise verify_requester and the guards directly,
without network."""

import base64
import tempfile
import time
import unittest

from securemail.crypto import Identity
from securemail.server import (AUTH_WINDOW, MAX_BODY, RATE_LIMIT, Store,
                               verify_requester)


class FakeHeaders(dict):
    pass


def _signed_headers(identity: Identity, username: str, ts: int | None = None):
    ts = ts if ts is not None else int(time.time())
    sig = identity.signing_key.sign(f"{username}|{ts}".encode())
    return FakeHeaders({
        "X-Timestamp": str(ts),
        "X-Signature": base64.b64encode(sig).decode(),
    })


class RequestSignatureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(f"{self.tmp.name}/t.db")
        self.alice = Identity.generate()
        self.store.register("alice", self.alice.public_signing_b64(),
                            self.alice.public_encryption_b64())

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_signature_accepted(self):
        self.assertTrue(verify_requester(self.store, "alice",
                                         _signed_headers(self.alice, "alice")))

    def test_unsigned_request_rejected(self):
        self.assertFalse(verify_requester(self.store, "alice", FakeHeaders()))

    def test_wrong_key_rejected(self):
        mallory = Identity.generate()
        self.assertFalse(verify_requester(self.store, "alice",
                                          _signed_headers(mallory, "alice")))

    def test_replay_outside_window_rejected(self):
        old_ts = int(time.time()) - AUTH_WINDOW - 10
        self.assertFalse(verify_requester(self.store, "alice",
                                          _signed_headers(self.alice, "alice", old_ts)))

    def test_unknown_user_rejected(self):
        self.assertFalse(verify_requester(self.store, "ghost",
                                          _signed_headers(self.alice, "ghost")))

    def test_garbage_headers_rejected(self):
        bad = FakeHeaders({"X-Timestamp": "not-a-number", "X-Signature": "!!!"})
        self.assertFalse(verify_requester(self.store, "alice", bad))


class GuardConfigTest(unittest.TestCase):
    def test_limits_are_sane(self):
        self.assertLessEqual(MAX_BODY, 1024 * 1024)   # never allow megabytes
        self.assertLessEqual(RATE_LIMIT, 1000)
        self.assertLessEqual(AUTH_WINDOW, 300)


if __name__ == "__main__":
    unittest.main()
