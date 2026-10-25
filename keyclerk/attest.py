# SPDX-License-Identifier: EUPL-1.2
"""TPM 2.0 attestation for edges (decision 0016): what an assured edge proves, and how KeyClerk checks it.

Three things, each the established TCG pattern (the one go-attestation and Keylime use):
  1. The endorsement key (EK) is a real TPM's: its fingerprint is pinned by the edge's officer on site, in the signed
     enrolment statement; where the TPM carries an EK certificate, that certificate must also chain to a manufacturer
     root the deployment lists (approvals of trust are configuration, never the edge's word).
  2. The attestation key (AK) lives in that same TPM: KeyClerk encrypts a challenge to the EK, bound to the AK's name
     (TPM2_MakeCredential, done here in software); only that TPM, holding both keys, can recover it
     (TPM2_ActivateCredential on the edge).
  3. The edge's measured state is fresh: every pull carries a quote, signed by the AK, over a nonce bound to that signed
     request, and over the PCRs the policy names (PCR 7, the Secure Boot state, by default).

Only parsing and checking happen here; policy (which PCRs, which values) is Rego (edge.rego), fed with the facts this
module returns. Every parser bounds its input and refuses trailing bytes.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

try:                                    # the TPM specification fixes AES-CFB for credentials; cryptography moved it here
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:                     # older cryptography
    from cryptography.hazmat.primitives.ciphers.modes import CFB

TPM_GENERATED = 0xFF544347
ST_ATTEST_QUOTE = 0x8018
ALG_RSA, ALG_SHA256, ALG_NULL, ALG_ECC, ALG_ECDSA, ALG_RSASSA, ALG_AES, ALG_CFB = 0x0001, 0x000B, 0x0010, 0x0023, 0x0018, 0x0014, 0x0006, 0x0043
ECC_NIST_P256 = 0x0003
CRED_MAGIC, CRED_VERSION = 0xBADCC0DE, 1          # the tpm2-tools file framing of a credential, for edges using it
MAX_STRUCT = 4096


class AttestError(ValueError):
    """The evidence does not hold: the message says which check failed."""


# --- reading TPM structures -----------------------------------------------------------------------------------------

class _R:
    def __init__(self, b: bytes):
        if not isinstance(b, (bytes, bytearray)) or len(b) > MAX_STRUCT:
            raise AttestError("structure missing or too large")
        self.b, self.i = bytes(b), 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.i + n > len(self.b):
            raise AttestError("structure is truncated")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def tpm2b(self) -> bytes:
        return self.take(self.u16())

    def end(self) -> None:
        if self.i != len(self.b):
            raise AttestError("trailing bytes after the structure")


@dataclass(frozen=True)
class Public:
    """A TPMT_PUBLIC: its bytes (what the name hashes), and the key it holds."""
    raw: bytes
    type: int
    name_alg: int
    attributes: int
    key: object

    @property
    def name(self) -> bytes:
        if self.name_alg != ALG_SHA256:
            raise AttestError("only SHA-256 names are accepted")
        return struct.pack(">H", ALG_SHA256) + hashlib.sha256(self.raw).digest()


# object attributes an AK must have: fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth, restricted, sign
AK_REQUIRED = 0x00000002 | 0x00000010 | 0x00000020 | 0x00000040 | 0x00010000 | 0x00040000


def parse_public(b: bytes) -> Public:
    """A TPM2B_PUBLIC (two-byte size, then TPMT_PUBLIC), or a bare TPMT_PUBLIC."""
    r = _R(b)
    if len(b) >= 2 and struct.unpack(">H", b[:2])[0] == len(b) - 2:
        r.take(2)
    start = r.i
    typ, name_alg, attrs = r.u16(), r.u16(), r.u32()
    r.tpm2b()                                                     # authPolicy
    if typ == ALG_ECC:
        sym = r.u16()
        if sym != ALG_NULL:
            r.take(4)                                             # keyBits, mode of a storage key
        scheme = r.u16()
        if scheme != ALG_NULL:
            r.u16()                                               # the scheme's hash
        curve, kdf = r.u16(), r.u16()
        if kdf != ALG_NULL:
            r.u16()
        x, y = r.tpm2b(), r.tpm2b()
        if curve != ECC_NIST_P256 or len(x) != 32 or len(y) != 32:
            raise AttestError("only P-256 keys are accepted")
        key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    elif typ == ALG_RSA:
        sym = r.u16()
        if sym != ALG_NULL:
            r.take(4)
        scheme = r.u16()
        if scheme != ALG_NULL:
            r.u16()
        bits, exp = r.u16(), r.u32()
        n = r.tpm2b()
        if bits < 2048 or len(n) * 8 != bits:
            raise AttestError("RSA keys are 2048 bits or more")
        key = rsa.RSAPublicNumbers(exp or 65537, int.from_bytes(n, "big")).public_key()
    else:
        raise AttestError("the key is neither RSA nor ECC")
    raw = r.b[start:r.i]
    r.end()
    return Public(raw, typ, name_alg, attrs, key)


def spki_sha256(key) -> str:
    """What the officer pins on site: SHA-256 over the key's SubjectPublicKeyInfo, hex."""
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


# --- 1. the EK: pinned on site, and chained to a manufacturer root where there is a certificate ------------------------

def check_ek(ek_public, pinned_sha256: str, cert_der: bytes | None, roots: list[bytes], intermediates: list[bytes] = (),
             at=None) -> dict:
    """The EK is the one the officer pinned, and (with a certificate) its certificate names that key and chains to one of
    the roots. Returns the facts the policy reads."""
    if not hmac.compare_digest(spki_sha256(ek_public), str(pinned_sha256).lower()):
        raise AttestError("the endorsement key is not the one the officer pinned on site")
    if cert_der is None:
        return {"ek_pinned": True, "ek_certified": False}
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except ValueError:
        raise AttestError("the EK certificate does not parse") from None
    if spki_sha256(cert.public_key()) != spki_sha256(ek_public):
        raise AttestError("the EK certificate is for another key")
    pool = [x509.load_pem_x509_certificate(c) if c.lstrip().startswith(b"-----") else x509.load_der_x509_certificate(c)
            for c in intermediates]
    anchors = [x509.load_pem_x509_certificate(c) if c.lstrip().startswith(b"-----") else x509.load_der_x509_certificate(c)
               for c in roots]
    if not anchors:
        raise AttestError("no manufacturer roots configured: an EK certificate cannot be checked")
    _chain(cert, pool, anchors, at)
    return {"ek_pinned": True, "ek_certified": True, "ek_issuer": cert.issuer.rfc4514_string()[:200]}


def _verify_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    if child.issuer != issuer.subject:
        return False
    try:
        child.verify_directly_issued_by(issuer)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def _chain(cert, pool, anchors, at, depth: int = 0) -> None:
    """EK certificates are not TLS certificates (no names, often no usages a TLS verifier wants): the chain is checked
    signature by signature, with validity times and CA flags on every issuer, up to a configured root."""
    from datetime import datetime, timezone
    now = at or datetime.now(timezone.utc)
    if depth > 4:
        raise AttestError("the EK certificate chain is too long")
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise AttestError("a certificate in the EK chain is outside its validity")
    for a in anchors:
        if _verify_by(cert, a) or cert == a:
            if not (a.not_valid_before_utc <= now <= a.not_valid_after_utc):
                raise AttestError("the manufacturer root is outside its validity")
            return
    for c in pool:
        if c != cert and _verify_by(cert, c):
            try:
                bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
            except x509.ExtensionNotFound:
                bc = None
            if not (bc and bc.ca):
                raise AttestError("an EK chain issuer is not a CA")
            return _chain(c, pool, anchors, at, depth + 1)
    raise AttestError("the EK certificate does not chain to a configured manufacturer root")


# --- 2. the AK lives in that TPM: credential activation --------------------------------------------------------------

def kdfa(key: bytes, label: bytes, context_u: bytes, context_v: bytes, bits: int) -> bytes:
    """TPM 2.0 KDFa with HMAC-SHA256 (SP 800-108 counter mode)."""
    out, i = b"", 1
    while len(out) * 8 < bits:
        out += hmac.new(key, struct.pack(">I", i) + label + b"\x00" + context_u + context_v + struct.pack(">I", bits),
                        hashlib.sha256).digest()
        i += 1
    return out[:bits // 8]


def check_ak(ak: Public) -> None:
    if ak.attributes & AK_REQUIRED != AK_REQUIRED:
        raise AttestError("the attestation key is not a restricted signing key fixed to its TPM")
    if ak.type != ALG_ECC and ak.type != ALG_RSA:
        raise AttestError("the attestation key type is not accepted")


def make_credential(ek: Public, ak_name: bytes, secret: bytes, seed: bytes | None = None) -> tuple[bytes, bytes]:
    """TPM2_MakeCredential in software, for an RSA EK with AES-128-CFB (the TCG default EK template): returns
    (TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET). Only the TPM holding this EK, and an object of this name, recovers it."""
    if ek.type != ALG_RSA:
        raise AttestError("credential activation here needs an RSA endorsement key")
    if not 16 <= len(secret) <= 32:
        raise AttestError("the challenge is 16 to 32 bytes")
    seed = seed or os.urandom(32)
    enc_seed = ek.key.encrypt(seed, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
                                                 label=b"IDENTITY\x00"))
    sym = kdfa(seed, b"STORAGE", ak_name, b"", 128)
    enc = Cipher(algorithms.AES(sym), CFB(b"\x00" * 16)).encryptor()
    enc_identity = enc.update(struct.pack(">H", len(secret)) + secret) + enc.finalize()
    mac = hmac.new(kdfa(seed, b"INTEGRITY", b"", b"", 256), enc_identity + ak_name, hashlib.sha256).digest()
    id_object = struct.pack(">H", 32) + mac + enc_identity
    return struct.pack(">H", len(id_object)) + id_object, struct.pack(">H", len(enc_seed)) + enc_seed


def credential_file(id_object: bytes, encrypted_secret: bytes) -> bytes:
    """The same, framed as tpm2-tools writes it (tpm2_activatecredential -i)."""
    return struct.pack(">II", CRED_MAGIC, CRED_VERSION) + id_object + encrypted_secret


# --- 3. the quote: fresh, from the activated AK, over the PCRs the policy reads --------------------------------------

def quote_nonce(edge: str, seconds: int, nonce: str) -> bytes:
    """What an edge quotes over on a pull: bound to its signed request (edge, time, the nonce the desk checks once)."""
    return hashlib.sha256(f"kc-edge-quote-v1|{edge}|{int(seconds)}|{nonce}".encode()).digest()


def verify_quote(ak: Public, msg: bytes, sig: bytes, pcr_values: dict[int, bytes], nonce: bytes) -> dict:
    """Check a TPM2_Quote: the AK signed it, it carries this nonce, and its PCR digest is over these PCR values.
    Returns the facts the policy reads: the PCRs (hex), the boot and reset counters, and the clock."""
    r = _R(msg)
    if r.u32() != TPM_GENERATED or r.u16() != ST_ATTEST_QUOTE:
        raise AttestError("not a TPM-generated quote")
    r.tpm2b()                                                     # qualifiedSigner
    extra = r.tpm2b()
    clock, resets, restarts, safe = r.u64(), r.u32(), r.u32(), r.u8()
    firmware = r.u64()
    banks = []
    for _ in range(r.u32()):
        alg, size = r.u16(), r.u8()
        bitmap = r.take(size)
        banks.append((alg, [i for i in range(size * 8) if bitmap[i // 8] >> (i % 8) & 1]))
    digest = r.tpm2b()
    r.end()
    if not hmac.compare_digest(extra, nonce):
        raise AttestError("the quote is over another nonce: not fresh for this request")
    if len(banks) != 1 or banks[0][0] != ALG_SHA256:
        raise AttestError("the quote is not over the SHA-256 PCR bank alone")
    selected = banks[0][1]
    if sorted(pcr_values) != selected:
        raise AttestError("the PCR values sent are not the PCRs quoted")
    if any(len(pcr_values[i]) != 32 for i in selected):
        raise AttestError("a PCR value is not 32 bytes")
    if not hmac.compare_digest(hashlib.sha256(b"".join(pcr_values[i] for i in selected)).digest(), digest):
        raise AttestError("the PCR values do not match the quoted digest")
    _verify_sig(ak, msg, sig)
    return {"pcrs": {str(i): pcr_values[i].hex() for i in selected}, "reset_count": resets, "restart_count": restarts,
            "clock_ms": clock, "clock_safe": bool(safe), "firmware": firmware}


def _verify_sig(ak: Public, msg: bytes, sig: bytes) -> None:
    r = _R(sig)
    alg, h = r.u16(), r.u16()
    if h != ALG_SHA256:
        raise AttestError("the quote is not signed with SHA-256")
    try:
        if alg == ALG_ECDSA and ak.type == ALG_ECC:
            rr, ss = r.tpm2b(), r.tpm2b()
            r.end()
            ak.key.verify(encode_dss_signature(int.from_bytes(rr, "big"), int.from_bytes(ss, "big")), msg, ec.ECDSA(hashes.SHA256()))
        elif alg == ALG_RSASSA and ak.type == ALG_RSA:
            s = r.tpm2b()
            r.end()
            ak.key.verify(s, msg, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise AttestError("the signature scheme does not fit the attestation key")
    except InvalidSignature:
        raise AttestError("the quote's signature is not the attestation key's") from None


def pcr_values_file(b: bytes, selected: list[int]) -> dict[int, bytes]:
    """tpm2_quote -F values: the selected PCR values, 32 bytes each, in order."""
    if len(b) != 32 * len(selected):
        raise AttestError("the PCR values file does not fit the selection")
    return {p: b[32 * k:32 * (k + 1)] for k, p in enumerate(sorted(selected))}


def quoted_pcrs(msg: bytes) -> list[int]:
    """The PCRs a quote's message selects (SHA-256 bank), to read a values blob in the same order."""
    r = _R(msg)
    if r.u32() != TPM_GENERATED or r.u16() != ST_ATTEST_QUOTE:
        raise AttestError("not a TPM-generated quote")
    r.tpm2b(), r.tpm2b()
    r.take(8 + 4 + 4 + 1 + 8)
    if r.u32() != 1:
        raise AttestError("the quote is not over the SHA-256 PCR bank alone")
    alg, size = r.u16(), r.u8()
    bitmap = r.take(size)
    if alg != ALG_SHA256:
        raise AttestError("the quote is not over the SHA-256 PCR bank alone")
    return [i for i in range(size * 8) if bitmap[i // 8] >> (i % 8) & 1]


def verify_quote_values(ak: Public, msg: bytes, sig: bytes, values: bytes, nonce: bytes) -> dict:
    """verify_quote, with the PCR values as tpm2_quote -F values writes them (32 bytes each, in PCR order)."""
    return verify_quote(ak, msg, sig, pcr_values_file(values, quoted_pcrs(msg)), nonce)
