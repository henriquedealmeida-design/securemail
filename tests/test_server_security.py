"""Security tests for the hardened server: request signatures, body cap,
rate limiting. These exercise verify_requester and the guards directly,
without network."""

import base64
import sqlite3
import tempfile
import time
import unittest

from securemail.addressing import address_id, identity_filename, is_address_id, normalize_address
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
        self.alice_id = address_id("henrique.de.almeida")
        self.store.register(self.alice_id, self.alice.public_signing_b64(),
                            self.alice.public_encryption_b64())

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_signature_accepted(self):
        self.assertTrue(verify_requester(self.store, self.alice_id,
                                         _signed_headers(self.alice, self.alice_id)))

    def test_unsigned_request_rejected(self):
        self.assertFalse(verify_requester(self.store, self.alice_id, FakeHeaders()))

    def test_wrong_key_rejected(self):
        mallory = Identity.generate()
        self.assertFalse(verify_requester(self.store, self.alice_id,
                                          _signed_headers(mallory, self.alice_id)))

    def test_replay_outside_window_rejected(self):
        old_ts = int(time.time()) - AUTH_WINDOW - 10
        self.assertFalse(verify_requester(self.store, self.alice_id,
                                          _signed_headers(self.alice, self.alice_id, old_ts)))

    def test_unknown_user_rejected(self):
        ghost = address_id("ghost")
        self.assertFalse(verify_requester(self.store, ghost,
                                          _signed_headers(self.alice, ghost)))

    def test_garbage_headers_rejected(self):
        bad = FakeHeaders({"X-Timestamp": "not-a-number", "X-Signature": "!!!"})
        self.assertFalse(verify_requester(self.store, self.alice_id, bad))


class GuardConfigTest(unittest.TestCase):
    def test_limits_are_sane(self):
        self.assertLessEqual(MAX_BODY, 1024 * 1024)   # never allow megabytes
        self.assertLessEqual(RATE_LIMIT, 1000)
        self.assertLessEqual(AUTH_WINDOW, 300)


class AddressingTest(unittest.TestCase):
    def test_email_is_normalized(self):
        self.assertEqual(
            normalize_address("Henrique.De.Almeida@Example.COM"),
            "henrique.de.almeida@example.com",
        )

    def test_local_part_expands_to_default_domain(self):
        self.assertEqual(
            normalize_address("henrique.de.almeida", "securemail.local"),
            "henrique.de.almeida@securemail.local",
        )

    def test_invalid_address_rejected(self):
        with self.assertRaises(ValueError):
            normalize_address("henrique/de/almeida")

    def test_identity_filename_is_path_safe(self):
        self.assertEqual(
            identity_filename("henrique.de.almeida+vip@example.com"),
            "henrique.de.almeida%2Bvip%40example.com.json",
        )

    def test_private_address_id_is_opaque_and_valid(self):
        private_id = address_id("henrique.de.almeida")
        self.assertTrue(is_address_id(private_id))
        self.assertNotIn("henrique.de.almeida", private_id)


class LegacyMigrationTest(unittest.TestCase):
    def test_legacy_user_table_is_migrated(self):
        tmp = tempfile.TemporaryDirectory()
        path = f"{tmp.name}/legacy.db"
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE users (username TEXT PRIMARY KEY, signing_pub TEXT NOT NULL, encryption_pub TEXT NOT NULL, registered_at REAL NOT NULL)"
        )
        conn.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?)",
            ("henrique.de.almeida@securemail.local", "sig", "enc", 1.0),
        )
        conn.commit()
        conn.close()
        store = Store(path)
        migrated = store.get_keys(address_id("henrique.de.almeida@securemail.local"))
        self.assertEqual(migrated["signing_pub"], "sig")
        self.assertEqual(migrated["encryption_pub"], "enc")
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
