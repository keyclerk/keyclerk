# SPDX-License-Identifier: EUPL-1.2
"""Proof of possession for bearer tokens (DPoP, RFC 9449), for front ends built by others.

A DPoP-bound access token names the thumbprint of a key its client holds (cnf.jkt); every request then carries a
fresh proof, a JWT signed with that key, naming the method, the URL, the time and the token's hash. A stolen token is
useless without the key. The desk requires DPoP for the clients named with --dpop-client.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from collections import OrderedDict

from keyclerk import guard

MAX_SKEW = 60
SEEN: OrderedDict = OrderedDict()
SEEN_LOCK = threading.Lock()
MAX_SEEN = 100000


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def thumbprint(jwk: dict) -> str:
    """RFC 7638: the SHA-256 of the key's required members, in order, without spaces."""
    if jwk.get("kty") == "EC":
        req = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    elif jwk.get("kty") == "RSA":
        req = {k: jwk[k] for k in ("e", "kty", "n")}
    else:
        raise guard.InputRejected("DPoP key type not accepted")
    return _b64e(hashlib.sha256(json.dumps(req, sort_keys=True, separators=(",", ":")).encode()).digest())


def _verify(jwk: dict, alg: str, data: bytes, sig: bytes) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    if alg == "ES256" and jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(_b64d(jwk["x"]), "big"), int.from_bytes(_b64d(jwk["y"]), "big"),
                                            ec.SECP256R1()).public_key()
        if len(sig) != 64:
            raise guard.InputRejected("DPoP signature malformed")
        pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), data,
                   ec.ECDSA(hashes.SHA256()))
    elif alg in ("RS256", "PS256") and jwk.get("kty") == "RSA":
        pub = rsa.RSAPublicNumbers(int.from_bytes(_b64d(jwk["e"]), "big"), int.from_bytes(_b64d(jwk["n"]), "big")).public_key()
        pad = padding.PKCS1v15() if alg == "RS256" else padding.PSS(padding.MGF1(hashes.SHA256()), 32)
        pub.verify(sig, data, pad, hashes.SHA256())
    else:
        raise guard.InputRejected("DPoP algorithm not accepted")


def check(proof: str, method: str, url: str, token: str, jkt: str | None) -> None:
    """Raise InputRejected unless the proof binds this request to the key the token names."""
    guard.text(proof or "", "DPoP proof", 8192)
    if not jkt:
        raise guard.InputRejected("the token is not bound to a key (DPoP required)")
    try:
        h64, p64, s64 = proof.split(".")
        header, claims = json.loads(_b64d(h64)), json.loads(_b64d(p64))
    except ValueError as e:
        raise guard.InputRejected("DPoP proof malformed") from e
    if not isinstance(header, dict) or not isinstance(claims, dict) or header.get("typ") != "dpop+jwt" \
            or not isinstance(header.get("jwk"), dict) or "d" in header["jwk"]:
        raise guard.InputRejected("DPoP proof malformed")
    try:
        _verify(header["jwk"], str(header.get("alg")), f"{h64}.{p64}".encode(), _b64d(s64))
    except guard.InputRejected:
        raise
    except Exception as e:   # noqa: BLE001
        raise guard.InputRejected("DPoP signature does not verify") from e
    if thumbprint(header["jwk"]) != jkt:
        raise guard.InputRejected("the DPoP key is not the token's")
    if claims.get("htm") != method or str(claims.get("htu", "")).split("?")[0].split("#")[0] != url:
        raise guard.InputRejected("the DPoP proof is for another request")
    now = time.time()
    if not isinstance(claims.get("iat"), (int, float)) or abs(now - claims["iat"]) > MAX_SKEW:
        raise guard.InputRejected("the DPoP proof is not fresh")
    if claims.get("ath") != _b64e(hashlib.sha256(token.encode()).digest()):
        raise guard.InputRejected("the DPoP proof is for another token")
    jti = f"{jkt}:{claims.get('jti')}"
    with SEEN_LOCK:                                   # check and record in one step: two requests, one wins
        if not claims.get("jti") or jti in SEEN:
            raise guard.InputRejected("the DPoP proof was used before")
        SEEN[jti] = now
        while SEEN and (now - next(iter(SEEN.values())) > 2 * MAX_SKEW or len(SEEN) > MAX_SEEN):
            SEEN.popitem(last=False)
