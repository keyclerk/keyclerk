# SPDX-License-Identifier: EUPL-1.2
"""The age v1 file format (age-encryption.org/v1), X25519 recipients only: what a backup is encrypted with
(decision 0019 point 1), so a custodian can decrypt one with the standard age tool when no KeyClerk runs.

    identity, recipient = keygen()             AGE-SECRET-KEY-1... and age1...
    blob = encrypt(data, [recipient, ...])
    data = decrypt(blob, [identity, ...])      AgeError says why it cannot

Header: the version line, one "-> X25519 <share>" stanza per recipient wrapping the file key, "---" and the header's
HMAC. Payload: a 16-byte nonce, then the STREAM of 64 KiB ChaCha20-Poly1305 chunks, the last one flagged.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

VERSION = b"age-encryption.org/v1"
CHUNK = 64 * 1024
TAG = 16
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


class AgeError(ValueError):
    pass


# --- bech32 (BIP 173, without the 90-character limit, as age uses it) ------------------------------------------------

def _polymod(values) -> int:
    gen, chk = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3), 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bits(data, frm: int, to: int, pad: bool) -> list[int]:
    acc, n, out, maxv = 0, 0, [], (1 << to) - 1
    for b in data:
        acc, n = acc << frm | b, n + frm
        while n >= to:
            n -= to
            out.append(acc >> n & maxv)
    if pad and n:
        out.append(acc << (to - n) & maxv)
    elif not pad and (n >= frm or acc << (to - n) & maxv):
        raise AgeError("bech32: padding bits are not zero")
    return out


def _b32encode(hrp: str, data: bytes) -> str:
    d = _bits(data, 8, 5, True)
    pm = _polymod(_expand(hrp) + d + [0] * 6) ^ 1
    return hrp + "1" + "".join(_CHARSET[x] for x in d + [pm >> 5 * (5 - i) & 31 for i in range(6)])


def _b32decode(s: str, hrp: str) -> bytes:
    if s.lower() != s and s.upper() != s:
        raise AgeError("bech32: mixed case")
    s = s.lower()
    pos = s.rfind("1")
    if s[:pos] != hrp or pos + 7 > len(s) or any(c not in _CHARSET for c in s[pos + 1:]):
        raise AgeError(f"not an age key with prefix {hrp}")
    d = [_CHARSET.index(c) for c in s[pos + 1:]]
    if _polymod(_expand(hrp) + d) != 1:
        raise AgeError("bech32: the checksum does not match")
    return bytes(_bits(d[:-6], 5, 8, False))


# --- keys ------------------------------------------------------------------------------------------------------------

def keygen() -> tuple[str, str]:
    identity = _b32encode("age-secret-key-", os.urandom(32)).upper()
    return identity, recipient(identity)


def _identity(identity: str) -> X25519PrivateKey:
    raw = _b32decode(identity.strip(), "age-secret-key-")
    if len(raw) != 32:
        raise AgeError("an age identity holds 32 bytes")
    return X25519PrivateKey.from_private_bytes(raw)


def _recipient(r: str) -> bytes:
    raw = _b32decode(r.strip(), "age")
    if len(raw) != 32:
        raise AgeError("an age recipient holds 32 bytes")
    return raw


def recipient(identity: str) -> str:
    return _b32encode("age", _identity(identity).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def identities(text: str) -> list[str]:
    """The identities of an identity file (age-keygen's output): every AGE-SECRET-KEY- line, comments left out."""
    return [ln.strip() for ln in text.splitlines() if ln.strip().upper().startswith("AGE-SECRET-KEY-1")]


# --- primitives ------------------------------------------------------------------------------------------------------

def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def _b64(b: bytes) -> bytes:
    return base64.b64encode(b).rstrip(b"=")


def _unb64(s: bytes) -> bytes:
    if b"=" in s or b"\r" in s or not all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" for c in s):
        raise AgeError("the header holds non-canonical base64")
    out = base64.b64decode(s + b"=" * (-len(s) % 4))
    if _b64(out) != s:
        raise AgeError("the header holds non-canonical base64")
    return out


def _wrap(file_key: bytes, pub: bytes) -> bytes:
    e = X25519PrivateKey.generate()
    share = e.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = e.exchange(X25519PublicKey.from_public_bytes(pub))
    key = _hkdf(shared, share + pub, b"age-encryption.org/v1/X25519")
    body = ChaCha20Poly1305(key).encrypt(b"\x00" * 12, file_key, None)
    return b"-> X25519 " + _b64(share) + b"\n" + _b64(body) + b"\n"


def _unwrap(args: list[bytes], body: bytes, ident: X25519PrivateKey) -> bytes | None:
    if len(args) != 1:
        raise AgeError("an X25519 stanza has one argument")
    share = _unb64(args[0])
    if len(share) != 32 or len(body) != 32:
        raise AgeError("an X25519 stanza holds a 32-byte share and a 32-byte body")
    try:
        shared = ident.exchange(X25519PublicKey.from_public_bytes(share))
    except ValueError:
        raise AgeError("an X25519 share gives the all-zero secret") from None
    pub = ident.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    try:
        return ChaCha20Poly1305(_hkdf(shared, share + pub, b"age-encryption.org/v1/X25519")).decrypt(
            b"\x00" * 12, body, None)
    except InvalidTag:
        return None                                              # a stanza for another recipient


def _nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


# --- encrypt and decrypt ---------------------------------------------------------------------------------------------

def encrypt_to(src: BinaryIO, dst: BinaryIO, recipients: list[str]) -> None:
    """Encrypt a stream chunk by chunk: memory stays at one chunk whatever the size."""
    if not recipients:
        raise AgeError("encrypting needs at least one recipient")
    file_key = os.urandom(16)
    header = VERSION + b"\n" + b"".join(_wrap(file_key, _recipient(r)) for r in recipients) + b"---"
    mac = hmac.new(_hkdf(file_key, b"", b"header"), header, hashlib.sha256).digest()
    nonce = os.urandom(16)
    aead = ChaCha20Poly1305(_hkdf(file_key, nonce, b"payload"))
    dst.write(header + b" " + _b64(mac) + b"\n" + nonce)
    i, cur = 0, src.read(CHUNK)
    while True:
        nxt = src.read(CHUNK) if len(cur) == CHUNK else b""
        dst.write(aead.encrypt(_nonce(i, not nxt), cur, None))
        if not nxt:
            return
        i, cur = i + 1, nxt


def encrypt(data: bytes, recipients: list[str]) -> bytes:
    out = io.BytesIO()
    encrypt_to(io.BytesIO(data), out, recipients)
    return out.getvalue()


def _header(blob: bytes) -> tuple[list[tuple[list[bytes], bytes]], bytes, bytes, int]:
    """The stanzas, the MAC'd header bytes, the MAC and where the payload starts."""
    lines, pos = [], 0
    while True:
        end = blob.find(b"\n", pos)
        if end < 0:
            raise AgeError("the header ends before its MAC line")
        lines.append(blob[pos:end])
        pos = end + 1
        if lines[-1].startswith(b"---"):
            break
    if lines[0] != VERSION:
        raise AgeError("not an age v1 file")
    stanzas, i = [], 1
    while i < len(lines) - 1:
        if not lines[i].startswith(b"-> "):
            raise AgeError("a header line is not a stanza")
        args = lines[i][3:].split(b" ")
        body, i = b"", i + 1
        while True:
            if i >= len(lines) - 1 or len(lines[i]) > 64:
                raise AgeError("a stanza body is not wrapped at 64 columns")
            body, i = body + lines[i], i + 1
            if len(lines[i - 1]) < 64:
                break
        stanzas.append((args, _unb64(body)))
    last = lines[-1]
    if not last.startswith(b"--- "):
        raise AgeError("the MAC line is malformed")
    return stanzas, blob[:pos - len(last) - 1 + 3], _unb64(last[4:]), pos


def decrypt_to(src: BinaryIO, dst: BinaryIO, ids: list[str]) -> None:
    """Decrypt a stream chunk by chunk; AgeError says why it cannot (output written before a failing chunk is not to be
    trusted: decrypt into a scratch file and use it only when this returns)."""
    head = b""
    while not head.endswith(b"\n") or b"\n---" not in head:
        line = src.readline(4096)
        if not line or len(head) > 65536:
            raise AgeError("the header ends before its MAC line")
        head += line
    stanzas, hdr, mac, _ = _header(head)
    keys = [_identity(i) for i in ids]
    file_key = None
    for args, body in stanzas:
        if args and args[0] == b"X25519":
            for k in keys:
                file_key = _unwrap(args[1:], body, k)
                if file_key is not None:
                    break
        if file_key is not None:
            break
    if file_key is None:
        raise AgeError("none of the given identities opens this file: it was encrypted to other recipients")
    if not hmac.compare_digest(hmac.new(_hkdf(file_key, b"", b"header"), hdr, hashlib.sha256).digest(), mac):
        raise AgeError("the header's MAC does not match: the header was changed")
    nonce = src.read(16)
    if len(nonce) != 16:
        raise AgeError("the payload has no nonce")
    aead, i, cur = ChaCha20Poly1305(_hkdf(file_key, nonce, b"payload")), 0, src.read(CHUNK + TAG)
    while True:
        nxt = src.read(CHUNK + TAG) if len(cur) == CHUNK + TAG else b""
        try:
            plain = aead.decrypt(_nonce(i, not nxt), cur, None)
        except InvalidTag:
            raise AgeError(f"chunk {i} does not authenticate: the file was changed or cut") from None
        if not nxt and not plain and i:
            raise AgeError("the last chunk is empty")
        dst.write(plain)
        if not nxt:
            return
        i, cur = i + 1, nxt


def decrypt(blob: bytes, ids: list[str]) -> bytes:
    out = io.BytesIO()
    decrypt_to(io.BytesIO(blob), out, ids)
    return out.getvalue()
