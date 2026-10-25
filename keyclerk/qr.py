# SPDX-License-Identifier: EUPL-1.2
"""The visit QR code (decision 0009, D2): a short token the desk signs, naming a visit and a party, never a person.

    kq1.<payload>.<signature>     payload: base64url JSON {v: visit id, p: party, n: serial, e: expiry (epoch), k: key id}
                                  signature: Ed25519 over "kq1." + payload, base64url

The desk keeps its own QR key (qr.key in the store, never in the records) and publishes the public half, so a
checkpoint cut off from the network can still check the signature. Two checks:
- online (the desk): signature, expiry, and the serial is the latest one issued for that party (issuing a new code
  revokes the old one); the visit's state is then decided by the policy (entry, unescorted). Revocation is seen at once.
- offline (a checkpoint with the public key): signature and expiry only, and it says so: a revocation or suspension
  since the code was issued is not seen.

The QR itself is a link to the desk's scan page (`<base>/#/scan/<token>`): any phone camera opens it, and the token
stays in the fragment of the address it was scanned from.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PREFIX = "kq1"
MAX_TOKEN = 400


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class QrKey:
    """The desk's QR signing key, kept in the store; created on first use."""

    def __init__(self, store_path: Path):
        f = store_path / "qr.key"
        if not f.exists():
            f.write_text(os.urandom(32).hex(), encoding="utf-8")
            try:
                os.chmod(f, 0o600)
            except OSError:
                pass
        self._priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read_text(encoding="utf-8").strip()))
        raw = self._priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public = _b64(raw)
        self.kid = hashlib.sha256(raw).hexdigest()[:12]

    def sign(self, visit_id: str, party: str, serial: int, expiry: int) -> str:
        payload = _b64(json.dumps({"v": visit_id, "p": party, "n": serial, "e": expiry, "k": self.kid},
                                  separators=(",", ":"), sort_keys=True).encode())
        head = f"{PREFIX}.{payload}"
        return f"{head}.{_b64(self._priv.sign(head.encode()))}"

    def published(self) -> dict:
        return {"kid": self.kid, "alg": "Ed25519", "key": self.public, "format": f"{PREFIX}.<payload>.<signature>"}


def digest(token: str) -> str:
    """What the records keep of an issued code: never the code itself."""
    return "sha256:" + hashlib.sha256(token.encode()).hexdigest()[:32]


def read(token: str) -> dict | None:
    """The payload, unverified (to know which visit and party a scan is about), or None when it is not a code."""
    try:
        if not isinstance(token, str) or len(token) > MAX_TOKEN:
            return None
        pre, payload, sig = token.split(".")
        if pre != PREFIX or not payload or not sig:
            return None
        p = json.loads(_unb64(payload))
        if not (isinstance(p, dict) and isinstance(p.get("v"), str) and isinstance(p.get("p"), str)
                and isinstance(p.get("n"), int) and isinstance(p.get("e"), int) and isinstance(p.get("k"), str)):
            return None
        return p
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def verify(public_b64: str, token: str, now: int) -> tuple[dict | None, str]:
    """(payload, "") for a code signed by this key and not expired; (None, why) otherwise. Signature and expiry only."""
    p = read(token)
    if p is None:
        return None, "this is not a KeyClerk visit code"
    head, sig = token.rsplit(".", 1)
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(public_b64)).verify(_unb64(sig), head.encode())
    except (InvalidSignature, ValueError):
        return None, "the code's signature does not check out"
    if now >= p["e"]:
        return None, "the code has expired"
    return p, ""


def verify_offline(public_b64: str, token: str, now: int) -> dict:
    """What a checkpoint without the network can say: signature and expiry, and that revocation is not seen."""
    p, why = verify(public_b64, token, now)
    return {"valid": p is not None, "mode": "offline", "visit_id": p and p["v"], "party": p and p["p"],
            "until": p and p["e"], "reason": why,
            "note": "offline: signature and expiry only; a new code, a suspension or a departure since it was issued is not seen"}


if __name__ == "__main__":      # python -m keyclerk.qr verify TOKEN PUBLIC_KEY   (an offline checkpoint)
    import sys
    import time
    if len(sys.argv) == 4 and sys.argv[1] == "verify":
        print(json.dumps(verify_offline(sys.argv[3], sys.argv[2], int(time.time())), indent=1))
        sys.exit(0)
    print(__doc__)
    sys.exit(2)
