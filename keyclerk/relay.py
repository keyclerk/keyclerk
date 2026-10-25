# SPDX-License-Identifier: EUPL-1.2
"""Ciphertext to a person's own key (decision 0014 points 7 and 8).

A person key is an X25519 key pair the browser derives from the person's passkey through WebAuthn PRF; only the public
half is registered. An edge encrypts a lease credential to it; the desk relays the ciphertext and holds nothing that
decrypts it. The envelope, `kc-relay-v1`:

    epk     the sender's one-time X25519 public key (32 bytes, base64url)
    nonce   12 random bytes (base64url)
    ct      AES-256-GCM ciphertext with its tag (base64url)
    context what the ciphertext is for (for example "lease:L-123"), bound as associated data

    shared = X25519(ephemeral private, recipient public)
    key    = HKDF-SHA256(shared, salt = epk || recipient public, info = "kc-relay-v1|" + context, 32 bytes)

The person key from a PRF output: private = HKDF-SHA256(prf output, salt empty, info "kc-person-key-v1", 32 bytes),
used as an X25519 private key (the curve clamps it). The browser does the same with WebCrypto (keyclerk/ui/app.js).
"""
from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

FORMAT = "kc-relay-v1"
PERSON_KEY_INFO = b"kc-person-key-v1"
MAX_PLAINTEXT = 4096                    # a lease credential, a break-glass value: small by design


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64d(s: str) -> bytes:
    if not isinstance(s, str) or len(s) > 16384:
        raise ValueError("not base64url text")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def public_key(value: str) -> bytes:
    """A registered person key: exactly 32 bytes of X25519, base64url."""
    raw = b64d(value)
    if len(raw) != 32:
        raise ValueError("an X25519 public key is 32 bytes")
    X25519PublicKey.from_public_bytes(raw)
    return raw


def person_key_from_prf(prf_output: bytes) -> tuple[bytes, bytes]:
    """(private, public) of the person key the browser derives from a PRF output (the reference for tests)."""
    if len(prf_output) < 32:
        raise ValueError("a PRF output is 32 bytes")
    seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=PERSON_KEY_INFO).derive(prf_output)
    priv = X25519PrivateKey.from_private_bytes(seed)
    return seed, priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _key(shared: bytes, epk: bytes, rpk: bytes, context: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=epk + rpk,
                info=(FORMAT + "|" + context).encode("utf-8")).derive(shared)


def encrypt(recipient_public: str, plaintext: bytes, context: str) -> dict:
    """What an edge does: encrypt to a person key. The desk never calls this for real secrets; tests and reference."""
    if len(plaintext) > MAX_PLAINTEXT:
        raise ValueError(f"at most {MAX_PLAINTEXT} bytes")
    rpk = public_key(recipient_public)
    eph = X25519PrivateKey.generate()
    epk = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = _key(eph.exchange(X25519PublicKey.from_public_bytes(rpk)), epk, rpk, context)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, context.encode("utf-8"))
    return {"format": FORMAT, "epk": b64e(epk), "nonce": b64e(nonce), "ct": b64e(ct), "context": context}


def decrypt(private: bytes, envelope: dict) -> bytes:
    """What the browser does (the reference for tests)."""
    check(envelope)
    priv = X25519PrivateKey.from_private_bytes(private)
    rpk = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    epk = b64d(envelope["epk"])
    key = _key(priv.exchange(X25519PublicKey.from_public_bytes(epk)), epk, rpk, envelope["context"])
    return AESGCM(key).decrypt(b64d(envelope["nonce"]), b64d(envelope["ct"]), envelope["context"].encode("utf-8"))


def check(envelope) -> None:
    """The shape the desk accepts and relays: it can check the form, never the content."""
    if not isinstance(envelope, dict) or set(envelope) != {"format", "epk", "nonce", "ct", "context"}:
        raise ValueError("an envelope has exactly format, epk, nonce, ct and context")
    if envelope["format"] != FORMAT:
        raise ValueError(f"format {FORMAT} only")
    if len(b64d(envelope["epk"])) != 32 or len(b64d(envelope["nonce"])) != 12:
        raise ValueError("epk is 32 bytes and nonce 12")
    ct = b64d(envelope["ct"])
    if not 16 < len(ct) <= MAX_PLAINTEXT + 16:
        raise ValueError("a ciphertext is between 1 and 4096 bytes plus its tag")
    ctx = envelope["context"]
    if not isinstance(ctx, str) or not 1 <= len(ctx) <= 120 or not ctx.isprintable():
        raise ValueError("a context is 1 to 120 printable characters")
