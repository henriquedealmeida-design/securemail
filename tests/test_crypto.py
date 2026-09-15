"""Crypto core tests: roundtrip, tamper detection, wrong-recipient isolation."""

import unittest

from securemail.crypto import Identity, decrypt_message, encrypt_message


class RoundtripTest(unittest.TestCase):
    def setUp(self):
        self.alice = Identity.generate()
        self.bob = Identity.generate()

    def _send(self, text="rendez-vous à 18h, lieu habituel"):
        env = encrypt_message(
            self.alice, "alice", "bob", self.bob.public_encryption_b64(), text
        )
        return env

    def test_roundtrip(self):
        env = self._send()
        plain = decrypt_message(self.bob, "bob", self.alice.public_signing_b64(), env)
        self.assertEqual(plain, "rendez-vous à 18h, lieu habituel")

    def test_envelope_is_opaque(self):
        env = self._send("secret content here")
        blob = str(env)
        self.assertNotIn("secret", blob)
        self.assertNotIn("content", blob)

    def test_tampered_ciphertext_rejected(self):
        env = self._send()
        raw = bytearray(__import__("base64").b64decode(env["ciphertext"]))
        raw[0] ^= 0xFF
        env["ciphertext"] = __import__("base64").b64encode(bytes(raw)).decode()
        with self.assertRaises(Exception):
            decrypt_message(self.bob, "bob", self.alice.public_signing_b64(), env)

    def test_forged_signature_rejected(self):
        env = self._send()
        mallory = Identity.generate()
        with self.assertRaises(Exception):
            decrypt_message(self.bob, "bob", mallory.public_signing_b64(), env)

    def test_wrong_recipient_cannot_decrypt(self):
        env = self._send()
        eve = Identity.generate()
        with self.assertRaises(Exception):
            decrypt_message(eve, "bob", self.alice.public_signing_b64(), env)

    def test_identity_serialization_roundtrip(self):
        raw = self.alice.to_json()
        clone = Identity.from_json(raw)
        self.assertEqual(
            self.alice.public_signing_b64(), clone.public_signing_b64()
        )
        self.assertEqual(
            self.alice.public_encryption_b64(), clone.public_encryption_b64()
        )


if __name__ == "__main__":
    unittest.main()
