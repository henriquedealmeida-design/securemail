# securemail

End-to-end encrypted messaging prototype — **the server never sees a single word of plaintext**.

Most "encrypted" messaging systems encrypt in transit and store plaintext (or
server-decryptable ciphertext) at rest. securemail explores the stricter
model: all cryptography happens on the client, and the server is reduced to a
blind relay that stores public keys and opaque envelopes. Even a full server
compromise leaks nothing about message contents.

## Cryptographic design

| Layer | Primitive | Purpose |
|-------|-----------|---------|
| Identity | Ed25519 keypair | signatures — proves *who* sent a message |
| Key exchange | X25519 (ephemeral-static ECDH) | establishes a shared secret per message |
| Key derivation | HKDF-SHA256 | derives the symmetric key, bound to sender+recipient |
| Content encryption | ChaCha20-Poly1305 | authenticated encryption of the message |

Sending a message:

1. Generate an **ephemeral** X25519 keypair (fresh for every message).
2. `ECDH(ephemeral_private, recipient_public)` → shared secret.
3. `HKDF(secret, info = "securemail-v1|sender|recipient")` → 32-byte key.
4. Encrypt with ChaCha20-Poly1305 (random 96-bit nonce).
5. **Sign** `ephemeral_pub ‖ nonce ‖ ciphertext` with the sender's Ed25519 key.

What the server stores for a queued message:

```
sender      : alice
ciphertext  : Z9PDbEPmd4Q/UFYB4hkZpbNLlyaJYfWg/0adYgVHNPilZnlPmGqBHETQR+rQ ...
nonce       : LgexcYNGEOpGumFt
signature   : yXy6Ct2hCkgdy+HrSGMhTolrRaPiF8qZMy/utaQuegtnj9hc2ApWdvRCDBwe ...
```

The recipient verifies the signature **before** decrypting — tampered or
forged messages are rejected, not decrypted.

## Quick start

```bash
pip install -r requirements.txt

# 1. start the blind relay
python -m securemail.server          # listens on 127.0.0.1:8471

# 2. create two identities (private keys stay local, mode 0600)
python -m securemail.client register alice
python -m securemail.client register bob

# 3. send an encrypted message
python -m securemail.client send alice bob "meet at 18:00, usual place"

# 4. bob fetches, verifies and decrypts
python -m securemail.client inbox bob
```

Identities live in `~/.securemail/<username>.json` with `0600` permissions,
like an SSH private key. Only the *public* keys are uploaded to the server.

## Security properties

- **Confidentiality against the server** — it only ever handles ciphertext.
- **Authenticity** — Ed25519 signatures; a forged sender key is rejected.
- **Integrity** — Poly1305 tag; any bit-flip in transit is detected.
- **Per-message forward secrecy of content keys** — each message uses a fresh
  ephemeral key; leaking one message key reveals nothing about others.
- **Authenticated API access** — `/inbox`, `/ack` and `/send` require a
  request signature (`Ed25519` over `"{username}|{timestamp}"`, verified
  against the registered public key, 60-second anti-replay window). Nobody
  can read, delete, or queue mail under someone else's name.
- **Abuse resistance** — request bodies capped at 64 KB, per-IP rate
  limiting, audit log of security events (registrations, sends, denied
  accesses) with no envelope or key material ever logged.

The hardening above followed an OWASP Top 10 self-review; the remaining
known gaps are listed below.

## Known limitations (it's a prototype, not Signal)

- No **asynchronous forward secrecy** for the long-term encryption key —
  stealing a recipient's identity file decrypts their stored envelopes.
  A real deployment would add the X3DH + Double Ratchet protocols.
- No protection of **metadata** (who talks to whom, when) beyond requiring
  authentication to read queues.
- The public-key directory is trusted — a malicious server could swap keys.
  Mitigation: out-of-band key fingerprint verification (not implemented).
- Plain HTTP by default — bind stays on 127.0.0.1; put the server behind a
  TLS reverse proxy before any network exposure.
- No replay protection on envelopes themselves.

These limitations are documented on purpose: knowing what a design does
*not* protect is part of the design.

## Project layout

```
securemail/
  crypto.py    keypairs, ECDH + HKDF + ChaCha20-Poly1305, signatures
  server.py    blind relay — stdlib http.server + sqlite3, signed endpoints
  client.py    CLI: register / send / inbox
tests/
  test_crypto.py           roundtrip, tamper detection, forgery, wrong-recipient
  test_server_security.py  request signatures, replay window, guard config
```

## Running the tests

```bash
python -m unittest discover -s tests -v
```

Covers: encryption roundtrip, ciphertext tampering, forged signatures,
decryption attempts by the wrong recipient, identity serialization, and
server-side request-signature verification (valid, missing, wrong-key,
replayed, unknown-user, garbage headers).

## License

MIT — see [LICENSE](LICENSE).
