# SPDX-License-Identifier: EUPL-1.2
"""Lists of trusted entities (ETSI TS 119 602, LoTE), read and kept (decision 0034 point 7, W0).

A list arrives as a compact JWS (ES256, ES384, RS256 or PS256) whose payload is the LoTE JSON and whose `x5c` leaf is
the scheme operator's signing certificate. It is accepted only when that leaf is one of the pinned signer certificates,
or is issued directly by one (the signer set the Official Journal publishes; its chain only, nothing found on the
way). The cache keeps each accepted JWS verbatim, so every read verifies again, and a floor per list: a sequence
number never goes back, and one sequence number never stands for two lists. Past its NextUpdate a list is stale and the
claims resting on it count as absent (0032 point 23). Nothing here touches the network: the fetcher hands in bytes.

    python -m keyclerk.lote read LIST.jws --signer SIGNER.pem [--signer ...]    what it lists, after verifying it
"""
import base64
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

MAX_BYTES = 8 * 1024 * 1024
MAX_ENTITIES = 20000
MAX_SEQUENCE = 2 ** 31 - 1                   # W1: a sequence a list can reach, never one that freezes the floor
MAX_STEP = 1000                              # W1: how far one accepted list moves the floor past the last one
LIST_SIGNING = x509.ObjectIdentifier("0.4.0.2231.3.0")   # id-tsl-kp-tslSigning (ETSI TS 119 612), as the OJ signers use
ALGS = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "RS256": hashes.SHA256(), "PS256": hashes.SHA256()}


class ListRefused(ValueError):
    """A list that is not accepted, with why."""


@dataclass(frozen=True)
class Service:
    entity: str
    name: str
    type: str
    status: str | None
    certificates: tuple[bytes, ...]


@dataclass(frozen=True)
class TrustedList:
    territory: str
    sequence: int
    issued: datetime
    next_update: datetime | None
    lote_type: str
    services: tuple[Service, ...] = field(default=())
    sha256: str = ""

    def anchors(self, service_type: str | None = None) -> list[bytes]:
        """The certificates (DER) of the listed services, of one type if named; a service whose status is present and
        is not granted is left out (a list without statuses lists only what it trusts)."""
        return [c for s in self.services if (service_type is None or s.type == service_type)
                and (s.status is None or s.status.rstrip("/").rsplit("/", 1)[-1].lower() == "granted")   # W3: not
                for c in s.certificates]                                                             # "notgranted"

    def stale(self, now: datetime) -> bool:
        return self.next_update is not None and now >= self.next_update


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _time(v) -> datetime | None:
    if isinstance(v, dict):                      # {"dateTime": ...} in the ETSI examples; a bare string in lists seen
        v = v.get("dateTime")
    if v is None:
        return None
    if not isinstance(v, str):
        raise ListRefused("a list time is not text")
    t = datetime.fromisoformat(v.replace("Z", "+00:00"))
    if t.tzinfo is None:
        raise ListRefused("a list time has no zone")
    return t.astimezone(timezone.utc)


def _text(v) -> str:
    if isinstance(v, list) and v and isinstance(v[0], dict):
        en = next((x for x in v if x.get("lang") == "en"), v[0])
        return str(en.get("value", ""))[:300]
    return str(v or "")[:300]


def _verify(alg: str, key, data: bytes, sig: bytes) -> None:
    h = ALGS[alg]
    if alg.startswith("ES"):
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise ListRefused(f"{alg} needs an EC key")
        n = len(sig) // 2
        key.verify(encode_dss_signature(int.from_bytes(sig[:n], "big"), int.from_bytes(sig[n:], "big")), data,
                   ec.ECDSA(h))
    else:
        if not isinstance(key, rsa.RSAPublicKey):
            raise ListRefused(f"{alg} needs an RSA key")
        pad = padding.PKCS1v15() if alg == "RS256" else padding.PSS(padding.MGF1(h), padding.PSS.DIGEST_LENGTH)
        key.verify(sig, data, pad, h)


def _ext(cert: x509.Certificate, kind):
    try:
        return cert.extensions.get_extension_for_class(kind).value
    except x509.ExtensionNotFound:
        return None


def _trusted(leaf: x509.Certificate, signers: list[x509.Certificate], now: datetime) -> None:
    """A pinned signer itself, or a leaf one of them issued as a CA (W1): the issuer a CA allowed to sign certificates,
    the leaf allowed to sign (digital signature) and to sign lists (id-tsl-kp-tslSigning)."""
    if not (leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc):
        raise ListRefused("the list's signing certificate is not valid now")
    for s in signers:
        if leaf == s:
            return
        try:
            leaf.verify_directly_issued_by(s)
        except (ValueError, TypeError, InvalidSignature):
            continue
        if not (s.not_valid_before_utc <= now <= s.not_valid_after_utc):
            continue
        bc, ku = _ext(s, x509.BasicConstraints), _ext(s, x509.KeyUsage)
        if bc is None or not bc.ca or (ku is not None and not ku.key_cert_sign):
            raise ListRefused("the pinned certificate that issued the list's signer is not a CA allowed to sign "
                              "certificates")
        lku, eku = _ext(leaf, x509.KeyUsage), _ext(leaf, x509.ExtendedKeyUsage)
        if lku is not None and not lku.digital_signature:
            raise ListRefused("the list's signing certificate may not make signatures (keyUsage)")
        if eku is None or LIST_SIGNING not in eku:
            raise ListRefused("the list's signing certificate is not for signing lists (id-tsl-kp-tslSigning)")
        return
    raise ListRefused("the list is not signed by a pinned signer, nor by a certificate one of them issued")


def verify(jws: bytes | str, signers: list[x509.Certificate], now: datetime | None = None) -> TrustedList:
    """The list, once its signature verifies under the pinned signers; ListRefused otherwise."""
    now = now or datetime.now(timezone.utc)
    raw = jws.encode() if isinstance(jws, str) else jws
    if len(raw) > MAX_BYTES:
        raise ListRefused(f"the list is larger than {MAX_BYTES} bytes")
    parts = raw.strip().split(b".")
    if len(parts) != 3 or not parts[1]:
        raise ListRefused("not a compact JWS with its payload attached")
    try:
        head = json.loads(_b64u(parts[0].decode()))
        payload = _b64u(parts[1].decode())
        sig = _b64u(parts[2].decode())
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise ListRefused("the JWS does not decode") from None
    if not isinstance(head, dict):                       # W3: a header is an object
        raise ListRefused("the JWS header is not an object")
    alg = head.get("alg")
    if alg not in ALGS:
        raise ListRefused(f"algorithm {alg!r} is not accepted")
    if head.get("crit"):
        raise ListRefused("a critical header this reader does not know")
    x5c = head.get("x5c")
    if not isinstance(x5c, list) or not x5c:
        raise ListRefused("no x5c: the signing certificate must travel with the list")
    try:
        if not isinstance(x5c[0], str):                  # W3: base64 text, nothing else
            raise ValueError("x5c holds base64 text")
        der = base64.b64decode(x5c[0], validate=True)
        leaf = x509.load_der_x509_certificate(der)
    except ValueError:
        raise ListRefused("the x5c certificate does not decode") from None
    t = head.get("x5t#S256")
    if t is not None and t != base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode():
        raise ListRefused("x5t#S256 does not match the certificate")
    _trusted(leaf, signers, now)
    try:
        _verify(alg, leaf.public_key(), parts[0] + b"." + parts[1], sig)
    except InvalidSignature:
        raise ListRefused("the list's signature does not verify") from None
    out = parse(payload)
    return TrustedList(**{**out.__dict__, "sha256": hashlib.sha256(raw.strip()).hexdigest()})


def parse(payload: bytes) -> TrustedList:
    """The LoTE JSON (wrapped in "LoTE" or bare), as data; nothing in it is trusted before verify. Any shape it does
    not expect is a refusal, never another error."""
    try:
        return _parse(payload)
    except ListRefused:
        raise
    except (TypeError, AttributeError, ValueError, KeyError, IndexError, OverflowError, RecursionError):
        raise ListRefused("the list is not in the LoTE shape") from None


def _parse(payload: bytes) -> TrustedList:
    try:
        doc = json.loads(payload)
    except ValueError:
        raise ListRefused("the list is not JSON") from None
    doc = doc.get("LoTE", doc) if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or not isinstance(doc.get("ListAndSchemeInformation"), dict):
        raise ListRefused("no ListAndSchemeInformation")
    si = doc["ListAndSchemeInformation"]
    seq = si.get("LoTESequenceNumber")
    if not isinstance(seq, int) or isinstance(seq, bool) or not 1 <= seq <= MAX_SEQUENCE:
        raise ListRefused(f"LoTESequenceNumber is not a whole number from 1 to {MAX_SEQUENCE}")
    issued = _time(si.get("ListIssueDateTime"))
    if issued is None:
        raise ListRefused("no ListIssueDateTime")
    entities = doc.get("TrustedEntitiesList") or []
    if not isinstance(entities, list) or len(entities) > MAX_ENTITIES:
        raise ListRefused("TrustedEntitiesList is not a list of a sane size")
    services = []
    for e in entities:
        name = _text(((e or {}).get("TrustedEntityInformation") or {}).get("TEName"))
        for s in (e or {}).get("TrustedEntityServices") or []:
            i = (s or {}).get("ServiceInformation") or {}
            certs = []
            for c in ((i.get("ServiceDigitalIdentity") or {}).get("X509Certificates") or []):
                try:
                    certs.append(base64.b64decode((c or {}).get("val", ""), validate=True))
                except ValueError:
                    raise ListRefused(f"a certificate of {name!r} does not decode") from None
            status = i.get("ServiceStatus")
            if status is not None and not isinstance(status, str):       # W3: a status is a URI
                raise ListRefused(f"a service status of {name!r} is not text")
            services.append(Service(name, _text(i.get("ServiceName")), str(i.get("ServiceTypeIdentifier") or ""),
                                    status, tuple(certs)))
    return TrustedList(str(si.get("SchemeTerritory") or ""), seq, issued, _time(si.get("NextUpdate")),
                       str(si.get("LoTEType") or ""), tuple(services))


class Cache:
    """Accepted lists, kept verbatim, and a floor per list name: the sequence never goes back."""

    def __init__(self, path: Path, signers: list[x509.Certificate]):
        self.path, self.signers = Path(path), signers
        self.path.mkdir(parents=True, exist_ok=True)

    def _floor(self) -> dict:
        """W3: a floor that does not read, or whose entries are not in their shape, refuses everything until the
        operator restores it; it is never taken as empty."""
        p = self.path / "floor.json"
        if not p.exists():
            return {}
        try:
            floor = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            floor = None
        ok = isinstance(floor, dict) and all(
            isinstance(v, dict) and isinstance(v.get("sequence"), int) and isinstance(v.get("sha256"), str)
            for v in floor.values())
        if not ok:
            raise ListRefused(f"the list floor {p} does not read: restore it from a backup")
        return floor

    @staticmethod
    def _name(name: str) -> str:
        if not isinstance(name, str) or not name.replace("-", "").replace("_", "").isalnum() or len(name) > 64:
            raise ListRefused("a list name is letters, digits, - and _")
        return name.lower()                                  # W3: one list, one name, whatever its case

    def _write(self, name: str, data: bytes) -> None:
        tmp = self.path / f".{name}.tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path / name)

    def put(self, name: str, jws: bytes, now: datetime | None = None) -> TrustedList:
        name = self._name(name)
        got = verify(jws, self.signers, now)
        floor = self._floor()
        old = floor.get(name)
        if old and got.sequence < old["sequence"]:
            raise ListRefused(f"{name}: sequence {got.sequence} is below the {old['sequence']} already accepted")
        if old and got.sequence == old["sequence"] and got.sha256 != old["sha256"]:
            raise ListRefused(f"{name}: sequence {got.sequence} already stands for another list")
        if old and got.sequence > old["sequence"] + MAX_STEP:      # W1: no one list freezes the floor
            raise ListRefused(f"{name}: sequence {got.sequence} jumps more than {MAX_STEP} past {old['sequence']}: "
                              "check the list by hand before accepting it")
        kind = [got.territory, got.lote_type]                       # W2: a name stands for one list
        if old and old.get("list") not in (None, kind):
            raise ListRefused(f"{name} holds the list of {old['list'][0]} ({old['list'][1]}), not this one")
        other = next((n for n, v in floor.items() if n != name and v.get("list") == kind), None)
        if other:
            raise ListRefused(f"this list ({kind[0]}, {kind[1]}) is kept as {other}: one list, one name")
        self._write(f"{name}.jws", jws.strip())
        floor[name] = {"sequence": got.sequence, "sha256": got.sha256, "list": kind}
        self._write("floor.json", json.dumps(floor, sort_keys=True, indent=1).encode())
        return got

    def get(self, name: str, now: datetime | None = None) -> TrustedList | None:
        """The cached list, verified again; None when there is none, it is stale, or it is not the one the floor names
        (then the claims resting on it count as absent)."""
        now = now or datetime.now(timezone.utc)
        name = self._name(name)
        p = self.path / f"{name}.jws"
        if not p.exists():
            return None
        got = verify(p.read_bytes(), self.signers, now)
        if (self._floor().get(name) or {}).get("sha256") != got.sha256 or got.stale(now):
            return None
        return got


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] != "read":
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        return 2
    signers = [x509.load_pem_x509_certificate(Path(argv[i + 1]).read_bytes())
               for i, a in enumerate(argv) if a == "--signer"]
    try:
        tl = verify(Path(argv[1]).read_bytes(), signers)
    except ListRefused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    print(f"{tl.territory} sequence {tl.sequence}, issued {tl.issued:%Y-%m-%d}, next update "
          f"{tl.next_update:%Y-%m-%d}" if tl.next_update else f"{tl.territory} sequence {tl.sequence}")
    for s in tl.services:
        print(f"- {s.entity}: {s.type} ({len(s.certificates)} certificate(s)){'' if s.status is None else ', ' + s.status}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
