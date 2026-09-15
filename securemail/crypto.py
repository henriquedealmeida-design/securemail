"""Cryptographic core.

Design goals:
- The server must never be able to read a message. All encryption and
  signing happens client-side; the server only stores opaque envelopes.
- Each user owns two keypairs:
    * Ed25519  — identity / signatures (proves *who* sent a message)
    * X25519   — encryption (used in an ephemeral-static ECDH to protect
      the message content)
- Sending a message:
    1. Generate an ephemeral X25519 keypair.
    2. ECDH(ephemeral_private, recipient_public) -> shared secret.
    3. HKDF-SHA256(shared secret, info = sender || recipient) -> 32-byte key.
    4. ChaCha20-Poly1305 encrypt the plaintext with a random 96-bit nonce.
    5. Sign (ephemeral_pub || nonce || ciphertext) with the Ed25519 key.
- The envelope sent to the server is a single compact JSON object; every
  field is base64. Without the recipient's private key it is indistinguishable
  from random noise.
"""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


class Identity:
    """A user's long-term keypairs (signing + encryption)."""

    def __init__(
        self,
        signing_key: ed25519.Ed25519PrivateKey,
        encryption_key: x25519.X25519PrivateKey,
    ):
        self.signing_key = signing_key
        self.encryption_key = encryption_key

    # -- construction ------------------------------------------------------

    @classmethod
    def generate(cls) -> "Identity":
        return cls(
            signing_key=ed25519.Ed25519PrivateKey.generate(),
            encryption_key=x25519.X25519PrivateKey.generate(),
        )

    # -- serialization -----------------------------------------------------

    def to_json(self) -> str:
        return json.dumps(
            {
                "signing_private": _b64(
                    self.signing_key.private_bytes(
                        serialization.Encoding.Raw,
                        serialization.PrivateFormat.Raw,
                        serialization.NoEncryption(),
                    )
                ),
                "encryption_private": _b64(
                    self.encryption_key.private_bytes(
                        serialization.Encoding.Raw,
                        serialization.PrivateFormat.Raw,
                        serialization.NoEncryption(),
                    )
                ),
            },
            indent=2,
        )

    @classmethod
    def from_json(cls, raw: str) -> "Identity":
        data = json.loads(raw)
        return cls(
            signing_key=ed25519.Ed25519PrivateKey.from_private_bytes(
                _unb64(data["signing_private"])
            ),
            encryption_key=x25519.X25519PrivateKey.from_private_bytes(
                _unb64(data["encryption_private"])
            ),
        )

    def save(self, path: str) -> None:
        # Identity files hold private keys: 0600, like an SSH key.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())

    @classmethod
    def load(cls, path: str) -> "Identity":
        with open(path, encoding="utf-8") as fh:
            return cls.from_json(fh.read())

    # -- public parts --------------------------------------------------------

    def public_signing_b64(self) -> str:
        return _b64(
            self.signing_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )

    def public_encryption_b64(self) -> str:
        return _b64(
            self.encryption_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )


def _derive_key(shared_secret: bytes, sender: str, recipient: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"securemail-v1|{sender}|{recipient}".encode("utf-8"),
    ).derive(shared_secret)


def encrypt_message(
    identity: Identity,
    sender: str,
    recipient: str,
    recipient_encryption_pub_b64: str,
    plaintext: str,
) -> dict:
    """Encrypt `plaintext` for `recipient`. Returns the opaque envelope."""
    ephemeral = x25519.X25519PrivateKey.generate()
    recipient_pub = x25519.X25519PublicKey.from_public_bytes(
        _unb64(recipient_encryption_pub_b64)
    )
    shared = ephemeral.exchange(recipient_pub)
    key = _derive_key(shared, sender, recipient)

    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext.encode("utf-8"), None)

    ephemeral_pub = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    signed_blob = ephemeral_pub + nonce + ciphertext
    signature = identity.signing_key.sign(signed_blob)

    return {
        "sender": sender,
        "ephemeral_pub": _b64(ephemeral_pub),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
        "signature": _b64(signature),
    }


def decrypt_message(
    identity: Identity,
    recipient: str,
    sender_signing_pub_b64: str,
    envelope: dict,
) -> str:
    """Verify the signature then decrypt. Raises on any tampering."""
    ephemeral_pub_bytes = _unb64(envelope["ephemeral_pub"])
    nonce = _unb64(envelope["nonce"])
    ciphertext = _unb64(envelope["ciphertext"])
    signature = _unb64(envelope["signature"])

    # 1. Authenticate the sender before touching the content.
    signing_pub = ed25519.Ed25519PublicKey.from_public_bytes(
        _unb64(sender_signing_pub_b64)
    )
    signing_pub.verify(signature, ephemeral_pub_bytes + nonce + ciphertext)

    # 2. Rebuild the shared secret and decrypt.
    ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    shared = identity.encryption_key.exchange(ephemeral_pub)
    key = _derive_key(shared, envelope["sender"], recipient)

    plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
