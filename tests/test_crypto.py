"""Crypto core tests: roundtrip, tamper detection, wrong-recipient isolation."""

import unittest

import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from securemail.addressing import address_id, normalize_address
from securemail.crypto import Identity, _b64, _derive_key, decrypt_message, encrypt_message


class RoundtripTest(unittest.TestCase):
    def setUp(self):
        self.alice = Identity.generate()
        self.bob = Identity.generate()
        self.alice_address = normalize_address("henrique.de.almeida")
        self.bob_address = normalize_address("contact")
        self.alice_id = address_id(self.alice_address)
        self.bob_id = address_id(self.bob_address)

    def _send(self, text="rendez-vous à 18h, lieu habituel"):
        env = encrypt_message(
            self.alice,
            self.alice_address,
            self.alice_id,
            self.bob_id,
            self.bob.public_encryption_b64(),
            text,
        )
        return env

    def test_roundtrip(self):
        env = self._send()
        plain = decrypt_message(
            self.bob, self.bob_id, self.alice.public_signing_b64(), env
        )
        self.assertEqual(plain["sender"], self.alice_address)
        self.assertEqual(plain["message"], "rendez-vous à 18h, lieu habituel")

    def test_envelope_is_opaque(self):
        env = self._send("secret content here")
        blob = str(env)
        self.assertNotIn("secret", blob)
        self.assertNotIn("content", blob)
        self.assertNotIn("henrique.de.almeida", blob)

    def test_tampered_ciphertext_rejected(self):
        env = self._send()
        raw = bytearray(__import__("base64").b64decode(env["ciphertext"]))
        raw[0] ^= 0xFF
        env["ciphertext"] = __import__("base64").b64encode(bytes(raw)).decode()
        with self.assertRaises(Exception):
            decrypt_message(self.bob, self.bob_id, self.alice.public_signing_b64(), env)

    def test_forged_signature_rejected(self):
        env = self._send()
        mallory = Identity.generate()
        with self.assertRaises(Exception):
            decrypt_message(self.bob, self.bob_id, mallory.public_signing_b64(), env)

    def test_wrong_recipient_cannot_decrypt(self):
        env = self._send()
        eve = Identity.generate()
        with self.assertRaises(Exception):
            decrypt_message(eve, self.bob_id, self.alice.public_signing_b64(), env)

    def test_legacy_envelope_is_still_readable(self):
        ephemeral = x25519.X25519PrivateKey.generate()
        shared = ephemeral.exchange(self.bob.encryption_key.public_key())
        key = _derive_key(shared, self.alice_address, self.bob_address)
        nonce = os.urandom(12)
        ciphertext = ChaCha20Poly1305(key).encrypt(
            nonce, b"legacy private message", None
        )
        ephemeral_pub = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        signed_blob = ephemeral_pub + nonce + ciphertext
        env = {
            "sender": self.alice_address,
            "ephemeral_pub": _b64(ephemeral_pub),
            "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext),
            "signature": _b64(self.alice.signing_key.sign(signed_blob)),
        }
        plain = decrypt_message(
            self.bob, self.bob_id, self.alice.public_signing_b64(), env, self.bob_address
        )
        self.assertEqual(plain["sender"], self.alice_address)
        self.assertEqual(plain["message"], "legacy private message")

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
