# SPDX-License-Identifier: EUPL-1.2
"""Edges (decision 0014 and its amendment 0014a): signed requests from an edge agent, the bundles it pulls, the ceiling
its officer signs, the enrolment statement, policy release manifests, and the reference verifier an agent conforms to.

Canonical form: JSON with sorted keys, no spaces, UTF-8, integers and strings only (no floats: other languages print
them differently). Every signed object travels as those exact bytes (base64) with Ed25519 signatures over them; a
verifier checks the signatures over the bytes, then parses them, then checks the parse is canonical. Nothing is ever
verified over a document a verifier serialises itself (amendment 0014d): one signing mode.
  sealed        {bytes, signature, key, key_id}: one signer (bundles, the officer's ceiling, notices, manifests); the
                object inside names its format and the signer's key id (first 16 hex characters of sha256 of the key)
  multi-signed  {bytes, signatures: [{key, key_id, signature}]}: every named key signs the same bytes, no other key
                (the enrolment and rotation statement: the officer and each node of the edge)

A request from an edge carries the header
    KeyClerk-Edge: <edge id>;<unix seconds>;<nonce, 16 to 64 base64url characters>;<signature hex>
signed over  "kc-edge-request-v2\\n" + edge id + "\\n" + METHOD + "\\n" + path with query + "\\n" + seconds + "\\n" + nonce
             + "\\n" + sha256(body) hex
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

BUNDLE_FORMAT = "kc-edge-bundle-v3"         # 0.23.0: the ceiling sealed as the officer signed it, modules by hash
CEILING_FORMAT = "kc-edge-ceiling-v2"       # amendment 0014d: sealed by the officer
OFFICER_FORMAT = "kc-edge-officer-v2"       # amendment 0014d: multi-signed by the officer and each node
STATEMENT_PURPOSES = ("enrolment", "rotation")
MAX_NODES = 2                                # an edge is one node, or two for the optional HA profile
RELEASE_FORMAT = "kc-policy-release-v1"
REQUEST_CONTEXT = "kc-edge-request-v2"
SKEW = 300                                   # seconds an edge's clock may differ from the desk's
NONCE = re.compile(r"[A-Za-z0-9_-]{16,64}")
EDGE_ID = re.compile(r"[a-z0-9][a-z0-9-]{1,62}")
CLASSES = ("low", "elevated", "privileged")
ISO = "%Y-%m-%dT%H:%M:%SZ"


# --- canonical bytes and signatures -------------------------------------------------------------------------------

MAX_SIGNED_INT = 2 ** 53 - 1                 # every language reads it exactly (int64, JavaScript)


def _plain(obj):
    if isinstance(obj, bool) or obj is None or isinstance(obj, str):
        return obj
    if isinstance(obj, int):
        if not 0 <= obj <= MAX_SIGNED_INT:
            raise TypeError(f"a signed integer is 0 to 2^53-1, not {str(obj)[:24]}")
        return obj
    if isinstance(obj, float):
        raise TypeError("no floats in signed objects: they do not print the same in every language")
    if isinstance(obj, datetime):
        return _iso(obj)
    if isinstance(obj, dict):
        if not all(isinstance(k, str) for k in obj):
            raise TypeError("object keys are strings")
        return {k: _plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_plain(v) for v in obj]
    raise TypeError(f"{type(obj).__name__} is not part of a signed object")


def canonical(obj) -> bytes:
    return json.dumps(_plain(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime(ISO)


TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
SIGNATURE_HEX = re.compile(r"[0-9a-f]{128}")


def _ts(s: str) -> datetime:
    """A signed time, exactly 2026-10-23T10:00:00Z (strptime alone accepts 2026-10-23T1:00:00Z)."""
    if not isinstance(s, str) or not TIME.fullmatch(s):
        raise ValueError(f"not a UTC time like 2026-10-23T10:00:00Z: {str(s)[:40]!r}")
    return datetime.strptime(s, ISO).replace(tzinfo=timezone.utc)


def _whole(x, low: int = 0) -> bool:
    """A JSON whole number, never a boolean (isinstance(True, int) holds in Python)."""
    return isinstance(x, int) and not isinstance(x, bool) and x >= low


def _refuse_float(s):
    raise ValueError(f"a float in signed bytes: {s[:20]}")


def _refuse_constant(s):
    raise ValueError(f"{s} in signed bytes")


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def key_id(hexkey: str) -> str:
    return sha256(bytes.fromhex(hexkey))[:16]


def load_public(hexkey: str) -> Ed25519PublicKey:
    if not isinstance(hexkey, str) or not re.fullmatch(r"[0-9a-f]{64}", hexkey):
        raise ValueError("an Ed25519 public key is 64 lower-case hex characters")
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hexkey))


def seal(key: Ed25519PrivateKey, obj: dict, fmt: str) -> dict:
    """An object as signed bytes: {"bytes": base64 canonical, "signature": hex, "key": hex, "key_id"}."""
    body = {**obj, "format": fmt, "key_id": key_id(public_hex(key))}
    raw = canonical(body)
    return {"bytes": base64.b64encode(raw).decode("ascii"), "signature": key.sign(raw).hex(), "key": public_hex(key),
            "key_id": body["key_id"]}


def _raw(b64) -> bytes:
    """Signed bytes from their base64, which must be canonical: one encoding per value, so no two encodings of one signature."""
    if not isinstance(b64, str):
        raise ValueError("bytes: base64 text")
    try:
        raw = base64.b64decode(b64, validate=True)
    except ValueError:
        raise ValueError("bytes: not base64") from None
    if base64.b64encode(raw).decode("ascii") != b64:
        raise ValueError("bytes: not canonical base64 (padding or trailing bits)")
    return raw


def _parse(raw: bytes) -> dict:
    """The object in signed bytes: canonical JSON, no floats, no NaN, an object."""
    try:
        obj = json.loads(raw, parse_float=_refuse_float, parse_constant=_refuse_constant)
        canon = canonical(obj)
    except (ValueError, TypeError, RecursionError) as e:
        raise ValueError(f"the signed bytes are not canonical: {str(e)[:120]}") from None
    if canon != raw:
        raise ValueError("the signed bytes are not canonical")
    if not isinstance(obj, dict):
        raise ValueError("the signed bytes hold an object")
    return obj


def _verifies(hexkey: str, sig, raw: bytes) -> bool:
    if not isinstance(sig, str) or not SIGNATURE_HEX.fullmatch(sig):
        return False
    try:
        load_public(hexkey).verify(bytes.fromhex(sig), raw)
        return True
    except Exception:   # noqa: BLE001 - malformed or wrong: not signed by that key
        return False


def unseal(sealed: dict, pinned_hex: str, fmt: str) -> dict:
    """The object inside signed bytes, or ValueError (never another exception): the pinned key and its key id outside
    and inside, a 128-hex signature, canonical base64, canonical JSON bytes without floats, the format."""
    if not isinstance(sealed, dict) or sealed.get("key") != pinned_hex:
        raise ValueError("a wrong signer: not the pinned key")
    if set(sealed) != {"bytes", "signature", "key", "key_id"}:
        raise ValueError("a sealed object is exactly {bytes, signature, key, key_id}")
    if sealed.get("key_id") != key_id(pinned_hex):
        raise ValueError("the sealed object's key_id is not the pinned key's")
    sig = sealed.get("signature")
    if not isinstance(sig, str) or not SIGNATURE_HEX.fullmatch(sig) or not isinstance(sealed.get("bytes"), str):
        raise ValueError("a sealed object is {bytes: base64, signature: 128 lower-case hex, key, key_id}")
    raw = _raw(sealed["bytes"])
    if not _verifies(pinned_hex, sig, raw):
        raise ValueError("a wrong signer: the signature does not verify over the bytes")
    obj = _parse(raw)
    if obj.get("format") != fmt or obj.get("key_id") != key_id(pinned_hex):
        raise ValueError(f"not a {fmt} signed by the pinned key")
    return obj


def bundle_digest(sealed: dict) -> str:
    """What a bundle says for its edge, without what every bundle changes (serial, issue time, format, key id): two
    bundles with the same digest give the edge the same leases, revocations, ceiling, policy and governed roles. The
    desk's long-poll compares it (decision 0026); an edge never needs it."""
    body = {k: v for k, v in opened(sealed).items() if k not in ("serial", "issued", "format", "key_id")}
    return sha256(canonical(body))


def opened(sealed: dict) -> dict:
    """What a sealed or multi-signed object says, without checking who signed it: for display and for a desk reading
    back what it verified when it stored it. Never a substitute for unseal."""
    if not isinstance(sealed, dict):
        raise ValueError("not a signed object")
    return _parse(_raw(sealed.get("bytes")))


# --- multi-signed objects: one set of bytes, a signature per named key (amendment 0014d) ---------------------------

def cosign(key: Ed25519PrivateKey, obj: dict, fmt: str = OFFICER_FORMAT) -> dict:
    """Start a multi-signed object from a document, or add this key's signature to one already started: every signer
    signs the same bytes, so nobody re-serialises anything. The document names its format; no key id inside (no one
    signer)."""
    if "bytes" in obj:
        raw = _raw(obj["bytes"])
        body = _parse(raw)
        sigs = list(obj.get("signatures") or [])
    else:
        body = {**obj, "format": fmt}
        raw = canonical(body)
        sigs = []
    if body.get("format") != fmt:
        raise ValueError(f"not a {fmt}")
    pub = public_hex(key)
    sigs = [s for s in sigs if isinstance(s, dict) and s.get("key") != pub]
    sigs.append({"key": pub, "key_id": key_id(pub), "signature": key.sign(raw).hex()})
    return {"bytes": base64.b64encode(raw).decode("ascii"), "signatures": sorted(sigs, key=lambda s: s["key"])}


def multi_signers(sealed) -> set[str]:
    """The keys whose signatures in a multi-signed object verify over its bytes (empty when it does not read): to tell
    which signer is missing. unseal_multi decides."""
    try:
        raw = _raw(sealed["bytes"])
        return {s["key"] for s in sealed["signatures"] if isinstance(s, dict) and isinstance(s.get("key"), str)
                and re.fullmatch(r"[0-9a-f]{64}", s["key"]) and _verifies(s["key"], s.get("signature"), raw)}
    except (ValueError, KeyError, TypeError):
        return set()


def unseal_multi(sealed: dict, required: list[str], fmt: str) -> dict:
    """The object inside a multi-signed object, or ValueError: signed by exactly the required keys (each once, with its
    key id and a 128-hex signature over the bytes, no other signature), canonical base64 and JSON, the format."""
    if not isinstance(sealed, dict) or set(sealed) != {"bytes", "signatures"}:
        raise ValueError("a multi-signed object is exactly {bytes, signatures}")
    sigs = sealed["signatures"]
    need = sorted(set(required))
    if not isinstance(sigs, list) or not all(isinstance(s, dict) and set(s) == {"key", "key_id", "signature"} for s in sigs):
        raise ValueError("signatures: a list of {key, key_id, signature}")
    keys = [s["key"] for s in sigs]
    if len(set(keys)) != len(keys):
        raise ValueError("a key signs once")
    if sorted(keys) != need:
        raise ValueError(f"signed by exactly {len(need)} keys: {', '.join(key_id(k) for k in need)}")
    raw = _raw(sealed["bytes"])
    for s in sigs:
        if s["key_id"] != key_id(s["key"]):
            raise ValueError(f"the key_id of {s['key'][:16]} is not its own")
        if not _verifies(s["key"], s["signature"], raw):
            raise ValueError(f"the signature of key {s['key_id']} does not verify over the bytes")
    obj = _parse(raw)
    if obj.get("format") != fmt:
        raise ValueError(f"not a {fmt}")
    return obj


def load_or_make_key(path: Path, allow_create: bool) -> Ed25519PrivateKey:
    """A signing key in its own file, created 0600 from the start (never briefly readable) and only when allowed: a key
    that went missing after edges pinned it must be restored, not silently replaced."""
    path = Path(path)
    if not path.exists():
        if not allow_create:
            raise RuntimeError(f"{path.name} is missing after edges pinned it: restore it from a backup")
        k = Ed25519PrivateKey.generate()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as h:
            h.write(k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(path.read_text(encoding="utf-8").strip()))


# --- signed requests ----------------------------------------------------------------------------------------------

def request_message(edge_id: str, method: str, path: str, seconds: int, nonce: str, body: bytes) -> bytes:
    return "\n".join((REQUEST_CONTEXT, edge_id, method.upper(), path, str(seconds), nonce, sha256(body or b""))).encode("utf-8")


def sign_request(key: Ed25519PrivateKey, edge_id: str, method: str, path: str, body: bytes = b"",
                 seconds: int | None = None, nonce: str | None = None) -> str:
    """The header value an edge sends (reference for agents and tests)."""
    import secrets as _s
    seconds = int(time.time()) if seconds is None else seconds
    nonce = nonce or base64.urlsafe_b64encode(_s.token_bytes(18)).rstrip(b"=").decode()
    sig = key.sign(request_message(edge_id, method, path, seconds, nonce, body)).hex()
    return f"{edge_id};{seconds};{nonce};{sig}"


class Replay:
    """Nonces seen within the skew window, per edge; bounded. In memory: a restart forgets them, which only lets a
    request from the last 5 minutes be replayed once (a low risk, accepted)."""

    def __init__(self, limit: int = 100_000):
        self.seen: dict[tuple[str, str], float] = {}
        self.limit, self.lock = limit, threading.Lock()

    def fresh(self, edge_id: str, nonce: str, now: float) -> bool:
        with self.lock:
            if len(self.seen) > self.limit or len(self.seen) % 512 == 0:
                self.seen = {k: t for k, t in self.seen.items() if now - t <= 2 * SKEW}
            if (edge_id, nonce) in self.seen:
                return False
            self.seen[(edge_id, nonce)] = now
            return True


def check_request(header: str, method: str, path: str, body: bytes, public_of, replay: Replay,
                  now: float | None = None) -> str:
    """The edge id, or ValueError. The same answer for an unknown edge and a bad signature (no id enumeration)."""
    now = time.time() if now is None else now
    parts = (header or "").split(";")
    if len(parts) != 4:
        raise ValueError("the KeyClerk-Edge header is edge;seconds;nonce;signature")
    edge_id, secs, nonce, sig = parts
    if not EDGE_ID.fullmatch(edge_id) or not secs.isdigit() or not NONCE.fullmatch(nonce) or not re.fullmatch(r"[0-9a-f]{128}", sig):
        raise ValueError("the KeyClerk-Edge header is malformed")
    if abs(now - int(secs)) > SKEW:
        raise ValueError("the edge's clock differs from the desk's by more than 5 minutes")
    pub = public_of(edge_id)
    try:
        load_public(pub or "").verify(bytes.fromhex(sig), request_message(edge_id, method, path, int(secs), nonce, body))
    except Exception:   # noqa: BLE001
        raise ValueError("not a request signed by an enrolled edge") from None
    if not replay.fresh(edge_id, nonce, now):
        raise ValueError("a nonce used before: replayed request refused")
    return edge_id


# --- enrolment: the officer and the edge both prove their keys -------------------------------------------------

def node(enrolment_key: str, unlock_key: str | None = None, tpm: dict | None = None) -> dict:
    """One machine of an edge in its statement: its enrolment key, its phoned-unlock key (kc-unlock-v2) and, with a TPM,
    its commitment (decision 0016: the EK the officer read on site, the AK's name, the PCR baseline)."""
    return {"enrolment_key": enrolment_key, "unlock_key": unlock_key, "tpm": tpm}


def officer_statement(edge_id: str, officer: str, officer_key: str, nodes: list[dict], purpose: str = "enrolment") -> dict:
    """What the edge's officer and every node of the edge sign, over the same bytes (cosign), at enrolment and at each
    rotation (amendment 0014d). Two nodes only for the HA profile."""
    if purpose not in STATEMENT_PURPOSES:
        raise ValueError("purpose: enrolment or rotation")
    if not 1 <= len(nodes) <= MAX_NODES:
        raise ValueError(f"an edge has 1 to {MAX_NODES} nodes")
    return {"format": OFFICER_FORMAT, "purpose": purpose, "edge": edge_id, "officer": officer, "officer_key": officer_key,
            "nodes": [node(n["enrolment_key"], n.get("unlock_key"), n.get("tpm")) for n in nodes]}


def statement_signers(st: dict) -> list[str]:
    """The keys that sign a statement: the officer's and each node's enrolment key."""
    return [st["officer_key"]] + [n["enrolment_key"] for n in st["nodes"]]


def tpm_commitment(tpm: dict) -> dict:
    """The part of an edge's TPM record the officer signs (decision 0016)."""
    import base64
    from keyclerk import attest as A
    ak = A.parse_public(base64.b64decode(tpm["ak_public"], validate=True))
    return {"ek_sha256": str(tpm["ek_sha256"]).lower(), "ak_name": ak.name.hex(),
            "pcr_baseline": {str(k): str(v).lower() for k, v in sorted(tpm["pcr_baseline"].items(), key=lambda x: int(x[0]))}}


QUOTE_HEADER_MAX = 4096


def parse_quote_header(h: str) -> tuple[bytes, bytes, bytes]:
    """The KeyClerk-Quote header of a pull: base64(message).base64(signature).base64(PCR values), as tpm2_quote writes
    them (decision 0016). Its nonce is attest.quote_nonce of the same request's KeyClerk-Edge values."""
    import base64
    import binascii
    if not isinstance(h, str) or len(h) > QUOTE_HEADER_MAX or h.count(".") != 2:
        raise ValueError("the KeyClerk-Quote header is message.signature.values, base64 each")
    try:
        return tuple(base64.b64decode(p, validate=True) for p in h.split("."))   # type: ignore[return-value]
    except (binascii.Error, ValueError):
        raise ValueError("the KeyClerk-Quote header is message.signature.values, base64 each") from None


# --- the ceiling --------------------------------------------------------------------------------------------------

CEILING_KEYS = {"format", "key_id", "edge", "serial", "persons", "roles", "targets", "classes", "max_lease_hours",
                "max_offline_hours", "profile", "remote_reach", "ports", "signed_at"}


def _strs(x) -> bool:
    return isinstance(x, list) and len(x) <= 500 and all(isinstance(v, str) and 0 < len(v) <= 256 for v in x)


def seal_ceiling(key: Ed25519PrivateKey, ceiling: dict) -> dict:
    """The officer seals a ceiling (amendment 0014d); the bundle carries it exactly as sealed."""
    return seal(key, {k: v for k, v in ceiling.items() if k not in ("format", "key_id")}, CEILING_FORMAT)


def check_ceiling(edge_id: str, officer_hex: str, sealed, floor: int = 0) -> tuple[list[str], dict | None]:
    """Errors in a sealed ceiling, and what it says; no errors means it may be used. Used by the desk and by the
    reference verifier alike."""
    try:
        ceiling = unseal(sealed, officer_hex, CEILING_FORMAT)
    except ValueError as e:
        if str(e).startswith("a wrong signer"):
            return ["the ceiling is not signed with the edge officer's key"], None
        return [f"the ceiling: {e}"], None
    if set(ceiling) != CEILING_KEYS:
        return [f"a ceiling has exactly {', '.join(sorted(CEILING_KEYS))}"], None
    errs = []
    if ceiling["edge"] != edge_id:
        errs.append("the ceiling names another edge")
    serial = ceiling["serial"]
    if not isinstance(serial, int) or isinstance(serial, bool) or serial < 1:
        errs.append("serial: a whole number from 1")
    elif serial < floor:
        errs.append(f"a ceiling older than the one held (serial {serial} below {floor})")
    for k in ("persons", "roles", "targets", "classes"):
        if not _strs(ceiling[k]):
            errs.append(f"{k}: a list of names")
    if _strs(ceiling["classes"]) and not set(ceiling["classes"]) <= set(CLASSES):
        errs.append("classes are low, elevated, privileged")
    for k, top in (("max_lease_hours", 24 * 366), ("max_offline_hours", 24 * 30)):
        v = ceiling[k]
        if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= top:
            errs.append(f"{k}: 0 to {top} hours")
    if ceiling["profile"] not in ("assured", "basic"):
        errs.append("profile: assured or basic")
    if ceiling["remote_reach"] not in ("off", "tunnel", "netbird"):
        errs.append("remote_reach: off, tunnel or netbird")
    if not isinstance(ceiling["ports"], list) or not all(isinstance(p, int) and not isinstance(p, bool) and 0 < p < 65536 for p in ceiling["ports"]):
        errs.append("ports: whole numbers from 1 to 65535")
    if not isinstance(ceiling["signed_at"], str) or not TIME.fullmatch(ceiling["signed_at"]):
        errs.append("signed_at: a UTC time like 2026-10-23T10:00:00Z")
    return errs, (ceiling if not errs else None)


# --- policy release manifests (the policy is not signed by the bundle key) -------------------------------------

def sign_release(key: Ed25519PrivateKey, modules: dict[str, str]) -> dict:
    """A manifest of module hashes, signed with a release key kept apart from the bundle key."""
    return seal(key, {"modules": dict(sorted(modules.items()))}, RELEASE_FORMAT)


# --- bundles ------------------------------------------------------------------------------------------------------

HEX64 = re.compile(r"[0-9a-f]{64}")


def module_refs(modules: dict[str, bytes]) -> dict:
    """What a bundle says about its policy modules: their hashes only. An agent fetches a module it does not hold by
    GET /edge/module/{sha256} and keeps it by hash (inlined, the modules made every pull ~520 KB)."""
    return {name: {"sha256": sha256(raw)} for name, raw in sorted(modules.items())}


def verify_module(raw: bytes, expected_sha256: str) -> list[str]:
    """A fetched policy module: exactly the bytes its bundle (and release manifest) named, and WebAssembly."""
    errs = []
    if not isinstance(raw, (bytes, bytearray)) or sha256(bytes(raw)) != expected_sha256:
        errs.append("the module's bytes are not the sha256 its bundle names")
    elif not bytes(raw).startswith(b"\x00asm"):
        errs.append("the module is not WebAssembly")
    return errs


def build_bundle(edge_id: str, serial: int, issued: datetime, horizons: dict, leases: list[dict], visit_leases: list[dict],
                 revoked: list[str], ceiling: dict | None, policy: dict, key: Ed25519PrivateKey,
                 governed_roles: list[str] | None = None) -> dict:
    """One sealed bundle. The newest bundle is complete: whatever an edge holds that is not in it has ended.
    leases: [{lease_id, person, username, email, key_id, target, role, class, from, until, max_session_hours}];
    visit_leases: [{lease_id, person, username, ssh_key, targets, role, from, until}];
    ceiling: the officer's sealed ceiling, exactly as the officer sealed it, or None;
    policy: {modules: {name: {sha256}}, release: sealed manifest or None, entrypoints};
    governed_roles (decision 0025): the edge roles KeyClerk governs here, carried as SCIM Group shapes
    [{displayName}]; None leaves the member out (no catalogue), an empty list is a signed "none governed"."""
    missing = sorted({x["class"] for x in leases} - set(horizons))
    if missing:                                             # a class without a horizon: refused at build time, never live anyway
        raise ValueError(f"leases of a class without a horizon: {', '.join(missing)}")
    body = {"edge": edge_id, "serial": serial, "issued": _iso(issued), "horizons": horizons, "leases": leases,
            "visit_leases": visit_leases, "revoked": sorted(revoked), "ceiling": ceiling, "policy": policy}
    if governed_roles is not None:
        body["governed_roles"] = [{"displayName": r} for r in sorted(set(governed_roles))]
    return seal(key, body, BUNDLE_FORMAT)


def verify_bundle(sealed: dict, pins: dict, state: dict, now: datetime, ceiling_check=None,
                  attested_profile: str | None = None) -> tuple[list[str], dict]:
    """The reference an edge agent conforms to. pins: {"edge": own id, "bundle_key": hex, "officer_key": hex,
    "release_key": hex or None} - all pinned on site, never taken from the desk. state: {"serial", "newest",
    "ceiling_serial"}; the caller stores the returned state only when there are no errors.
    ceiling_check(ceiling, entry) -> {"allow", "refusals"}: the ceiling policy (the agent runs the module it verified),
    for leases and visit leases alike. attested_profile: what this edge attests itself to be ("assured", "basic" or
    None); a visit lease needs an assured edge by its ceiling and its attestation, so without one every visit is refused.
    Returns (errors, what applies now)."""
    try:
        b = unseal(sealed, pins["bundle_key"], BUNDLE_FORMAT)
    except ValueError as e:
        return [str(e)], {}
    shape = _bundle_shape(b)
    if shape:
        return shape, {}
    try:
        return _verify_bundle(b, pins, state, now, ceiling_check, attested_profile)
    except (KeyError, TypeError, ValueError) as e:        # a verifier refuses, it never raises
        return [f"a malformed bundle: {str(e)[:200]}"], {}


def _bundle_shape(b: dict) -> list[str]:
    """What a bundle must hold before anything is read from it, so a malformed bundle is refused, never raises."""
    errs = []
    need = {"edge": str, "serial": int, "issued": str, "horizons": dict, "leases": list, "visit_leases": list, "revoked": list}
    for k, t in need.items():
        if not isinstance(b.get(k), t):
            errs.append(f"a bundle has {k}")
    if errs:
        return errs
    if not _whole(b["serial"], 1):
        errs.append("serial: a whole number from 1")
    for k in ("issued",):
        try:
            _ts(b[k])
        except ValueError as e:
            errs.append(f"{k}: {e}")
    if not all(isinstance(k, str) and _whole(v) for k, v in b["horizons"].items()):
        errs.append("horizons: hours per class, whole numbers")
    if not all(isinstance(r, str) for r in b["revoked"]):
        errs.append("revoked: lease ids")
    for kind in ("leases", "visit_leases"):
        for x in b[kind]:
            if not isinstance(x, dict) or not isinstance(x.get("lease_id"), str):
                errs.append(f"{kind}: each has a lease_id")
                continue
            try:
                _ts(x.get("from")), _ts(x.get("until"))
            except ValueError as e:
                errs.append(f"{x['lease_id']}: {e}")
            if kind == "leases" and not (isinstance(x.get("class"), str) and isinstance(x.get("target"), str)
                                         and isinstance(x.get("person"), str)):
                errs.append(f"{x['lease_id']}: a lease names its person, target and class")
    if b.get("ceiling") is not None and not isinstance(b["ceiling"], dict):
        errs.append("ceiling: the officer's sealed ceiling or null")
    if b.get("policy") is not None and not isinstance(b["policy"], dict):
        errs.append("policy: {modules, release, entrypoints}")
    if "governed_roles" in b:                           # decision 0025: absent is no catalogue, never "none governed"
        g = b["governed_roles"]
        names = [x.get("displayName") for x in g if isinstance(x, dict)] if isinstance(g, list) else None
        if (names is None or len(names) != len(g) or not all(isinstance(n, str) and n for n in names)
                or any(set(x) - {"displayName", "externalId"} or not isinstance(x.get("externalId", ""), str) for x in g)):
            errs.append("governed_roles: a list of {displayName, externalId?}, both strings")
        elif len(set(names)) != len(names):
            errs.append("governed_roles: each role once")
    return errs


def _verify_bundle(b: dict, pins: dict, state: dict, now: datetime, ceiling_check,
                   attested_profile: str | None = None) -> tuple[list[str], dict]:
    errs = []
    if b.get("edge") != pins["edge"]:
        errs.append("a bundle for another edge")
    if not _whole(b.get("serial"), 1) or b["serial"] <= int(state.get("serial", 0)):
        errs.append(f"serial {b.get('serial')} is not above the floor {state.get('serial', 0)}: an old bundle replayed")
    issued = _ts(b["issued"])
    if issued > now + timedelta(seconds=SKEW):
        errs.append("issued in the future: refused (a clock pushed forward must not stretch leases)")
    newest = _ts(state["newest"]) if state.get("newest") else None
    if newest and now < newest - timedelta(seconds=SKEW):
        errs.append("the clock is before the newest signed time seen: refused (time never goes back)")
    if newest and issued < newest - timedelta(seconds=SKEW):
        errs.append("issued before the newest signed time seen")
    rel = (b.get("policy") or {}).get("release")
    modules = (b.get("policy") or {}).get("modules") or {}
    if not isinstance(modules, dict):
        errs.append("policy.modules: {name: {sha256}}")
        modules = {}
    for name, mod in modules.items():                      # by hash only; the bytes are checked when fetched
        if not isinstance(mod, dict) or set(mod) != {"sha256"} or not isinstance(mod["sha256"], str) \
                or not HEX64.fullmatch(mod["sha256"]):
            errs.append(f"policy module {name}: {{sha256}} only, 64 lower-case hex (its bytes come from GET /edge/module)")
    if errs:
        return errs, {}
    if pins.get("release_key"):
        try:
            manifest = unseal(rel or {}, pins["release_key"], RELEASE_FORMAT)
            for name, mod in modules.items():
                if manifest["modules"].get(name) != mod["sha256"]:
                    errs.append(f"policy module {name} is not the released one")
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            errs.append(f"the policy release does not verify: {e}")
    c = b.get("ceiling")
    floor = int(state.get("ceiling_serial", 0))
    if c is None:
        if b["leases"] or b["visit_leases"]:
            errs.append("leases without a ceiling: refused (fail closed)")
        if floor:
            errs.append("a bundle without the ceiling the edge already holds")
    doc = None
    if c is not None:
        cerrs, doc = check_ceiling(pins["edge"], pins["officer_key"], c, floor)
        errs += cerrs
    if errs:
        return errs, {}
    cap = int(doc["max_offline_hours"]) if doc else 0
    age = now - issued
    live, visits, refused = [], [], []
    for x in b["leases"]:
        if ceiling_check is not None:
            d = ceiling_check(doc, {"kind": "lease", "person": x["person"], "roles": x.get("roles", []), "targets": [x["target"]],
                                    "class": x["class"], "hours": max(1, int((_ts(x["until"]) - _ts(x["from"])).total_seconds() // 3600))})
            if not d["allow"]:
                refused.append(x["lease_id"])
                continue
        if x["class"] not in b["horizons"]:                 # no horizon: never live (an edge applies no lease it cannot bound)
            continue
        horizon = min(int(b["horizons"][x["class"]]), cap)         # the ceiling narrows offline validity
        if _ts(x["from"]) <= now < _ts(x["until"]) and age <= timedelta(hours=horizon) and x["lease_id"] not in b["revoked"]:
            live.append(x)
    for x in b["visit_leases"]:
        if ceiling_check is not None:                   # the officer's ceiling holds for visits too, not only at the desk
            d = ceiling_check(doc, {"kind": "visit", "person": x["person"], "targets": list(x["targets"]),
                                    "hours": int((_ts(x["until"]) - _ts(x["from"])).total_seconds() // 3600),
                                    "attested_profile": attested_profile})
            if not d["allow"]:
                refused.append(x["lease_id"])
                continue
        if _ts(x["from"]) <= now < _ts(x["until"]) and x["lease_id"] not in b["revoked"]:
            visits.append(x)
    return [], {"leases": live, "visit_leases": visits, "revoked": b["revoked"], "refused_by_ceiling": refused,
                "governed_roles": [x["displayName"] for x in b["governed_roles"]] if "governed_roles" in b else None,
                "state": {"serial": b["serial"], "newest": max(issued, newest or issued).strftime(ISO),   # signed times only
                          "ceiling_serial": int(doc["serial"]) if doc else floor}}


# --- slice D: carried visit leases, phoned unlock, the ended notice, bundle key rollover (decision 0014c) ------------

CARRIED_FORMAT = "kc-edge-carried-v1"
ENDED_FORMAT = "kc-edge-ended-v2"            # bound to the enrolment keys it ends
ROLLOVER_FORMAT = "kc-edge-key-rollover-v1"


def verify_carried(sealed: dict, pins: dict, state: dict, now: datetime) -> tuple[list[str], dict]:
    """A visit lease a person carries to an edge on a laptop or phone: signed with the bundle key for this
    edge, inside its own window, above the per-person floor (a newer carried lease replaces an older one). The agent
    also checks the person holds the private half of `ssh_key` (an SSH signature at its local port: the edge agent's side).
    state: {"carried": {person: highest serial applied}}."""
    try:
        c = unseal(sealed, pins["bundle_key"], CARRIED_FORMAT)
        t0, t1 = _ts(c.get("from")), _ts(c.get("until"))
    except ValueError as e:
        return [str(e)], {}
    errs = []
    if c.get("edge") != pins["edge"]:
        errs.append("a carried lease for another edge")
    if not isinstance(c.get("person"), str):
        return ["a carried lease names its person"], {}
    floor = int((state.get("carried") or {}).get(c["person"], 0))
    if not _whole(c.get("carried_serial"), 1) or c["carried_serial"] <= floor:
        errs.append(f"a carried lease at or below the floor {floor} for that person: replayed or replaced")
    if not (t0 <= now < t1):
        errs.append("outside its window")
    if errs:
        return errs, {}
    return [], {"lease": c, "state": {"carried": {**(state.get("carried") or {}), c["person"]: c["carried_serial"]}}}


def ended_notice(key: Ed25519PrivateKey, edge_id: str, ended: datetime, reason: str, enrolment_keys: list[str]) -> dict:
    """The sealed notice an ended edge gets instead of a bundle (decision 0014c), naming the key ids of the enrolment
    keys it ends: a captured notice never ends another edge or a later enrolment."""
    return seal(key, {"edge": edge_id, "ended": _iso(ended), "reason": reason,
                      "enrolment_keys": sorted({key_id(k) for k in enrolment_keys})}, ENDED_FORMAT)


EMAIL_FORMAT = "kc-edge-email-v1"           # edge protocol 1.3 (decision 0028 point 5)
MAX_EMAIL = 320


def email_answer(key: Ed25519PrivateKey, edge_id: str, lease_id: str, person: str, email: str | None, nonce: str,
                 issued: datetime) -> dict:
    """The verified address of a lease's person, sealed for one signed request of that edge (its nonce)."""
    return seal(key, {"edge": edge_id, "lease_id": lease_id, "person": person, "email": email, "nonce": nonce,
                      "issued": issued.strftime(ISO)}, EMAIL_FORMAT)


def verify_email(sealed: dict, pins: dict, lease_id: str, nonce: str) -> tuple[list[str], dict]:
    """The answer to an edge's own e-mail request (GET /api/v1/edge/lease/{lease_id}/email): signed by the pinned
    bundle key, for this edge and this lease, answering this request (its nonce: an answer to another request is a
    replay). The address is used to set the gateway's credential and never kept in the agent's bundle state; email
    null means the broker holds no verified address for that person."""
    try:
        m = unseal(sealed, pins["bundle_key"], EMAIL_FORMAT)
        _ts(m.get("issued"))
    except (ValueError, KeyError, TypeError) as e:
        return [str(e)], {}
    errs = []
    if m.get("edge") != pins["edge"]:
        errs.append("an answer for another edge")
    if m.get("lease_id") != lease_id:
        errs.append("an answer for another lease")
    if m.get("nonce") != nonce:
        errs.append("an answer to another request: replayed")
    if not isinstance(m.get("person"), str):
        errs.append("an answer names its person")
    email = m.get("email")
    if email is not None and not (isinstance(email, str) and 3 <= len(email) <= MAX_EMAIL and "@" in email):
        errs.append("an address is text with an @, at most 320 characters, or null")
    return errs, (m if not errs else {})


def verify_ended(sealed: dict, pins: dict, own_enrolment_key: str) -> tuple[list[str], dict]:
    """An ended notice an agent acts on (it stops and wipes): signed by the pinned bundle key, for this edge, naming
    this node's enrolment key."""
    try:
        n = unseal(sealed, pins["bundle_key"], ENDED_FORMAT)
        _ts(n.get("ended"))
    except (ValueError, KeyError, TypeError) as e:
        return [str(e)], {}
    errs = []
    if n.get("edge") != pins["edge"]:
        errs.append("an ended notice for another edge")
    keys = n.get("enrolment_keys")
    if not isinstance(keys, list) or key_id(own_enrolment_key) not in keys:
        errs.append("an ended notice for other enrolment keys: not this node")
    return errs, (n if not errs else {})


# --- kc-unlock-v2: phoned unlock over P-256, so the edge's key can live in its TPM (TPMs lack Curve25519)

UNLOCK_CONTEXT = "kc-unlock-v2"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unlock_private(scalar_hex: str):
    """A P-256 private key from its 32-byte scalar, hex (the desk's file, or a software key on an edge without a TPM)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    if not isinstance(scalar_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", scalar_hex.strip()):
        raise ValueError("a P-256 private key is its scalar, 64 lower-case hex characters")
    return ec.derive_private_key(int(scalar_hex.strip(), 16), ec.SECP256R1())


def new_unlock_private() -> str:
    from cryptography.hazmat.primitives.asymmetric import ec
    return format(ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value, "064x")


def unlock_public(private) -> str:
    """The public half: the uncompressed SEC1 point (65 bytes), base64url without padding (what TPM2_ReadPublic's x and
    y give, prefixed 04)."""
    from cryptography.hazmat.primitives.serialization import Encoding as Enc, PublicFormat as PubF
    return _b64u(private.public_key().public_bytes(Enc.X962, PubF.UncompressedPoint))


def load_unlock_public(b64: str):
    """A phoned-unlock public key: P-256, uncompressed SEC1, base64url without padding; the point is on the curve."""
    from cryptography.hazmat.primitives.asymmetric import ec
    if not isinstance(b64, str) or not re.fullmatch(r"[A-Za-z0-9_-]{87}", b64):
        raise ValueError("an unlock key is a P-256 point, 65 bytes uncompressed, base64url without padding (kc-unlock-v2)")
    raw = base64.urlsafe_b64decode(b64 + "=")
    if _b64u(raw) != b64 or raw[0] != 4:
        raise ValueError("an unlock key is an uncompressed P-256 point (04 x y), canonical base64url")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError:
        raise ValueError("an unlock key is a point on P-256") from None


def unlock_secret(own_private, desk_public: str, edge_public: str, edge_id: str, node_key_id: str) -> bytes:
    """The phoned-unlock secret the desk and the edge node each compute from their own P-256 key and the other's
    public key (ECDH; on a TPM, TPM2_ECDH_ZGen): nothing secret crosses the network. The derivation
    binds the edge, the node (its enrolment key id) and both public keys."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    own = unlock_public(own_private)
    if own == desk_public:
        peer = edge_public
    elif own == edge_public:
        peer = desk_public
    else:
        raise ValueError("the own key is neither the desk's nor the edge node's unlock key")
    shared = own_private.exchange(ec.ECDH(), load_unlock_public(peer))
    info = "|".join((UNLOCK_CONTEXT, edge_id, node_key_id, desk_public, edge_public)).encode("utf-8")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def unlock_code(secret: bytes, edge_id: str, node_key_id: str, person: str, key_fingerprint: str, target: str,
                nonce: str, minutes: int) -> str:
    """A short code a second person reads over the phone; the edge node recomputes it. 10 base32 characters (50 bits);
    the edge limits attempts (edge.rego unlock_per_hour). No field holds a | or a line break."""
    import hmac
    fields = (UNLOCK_CONTEXT, edge_id, node_key_id, person, key_fingerprint, target, nonce, str(minutes))
    if any(not isinstance(f, str) or not f or "|" in f or "\n" in f or "\r" in f for f in fields):
        raise ValueError("an unlock field is non-empty text without | or a line break")
    msg = "|".join(fields).encode("utf-8")
    return base64.b32encode(hmac.new(secret, msg, hashlib.sha256).digest()).decode("ascii")[:10]


def accept_rollover(sealed: dict, pinned_hex: str) -> str:
    """A bundle key rollover signed by the pinned (old) key names its successor; returns the new key to pin."""
    r = unseal(sealed, pinned_hex, ROLLOVER_FORMAT)
    load_public(r["new_key"])
    return r["new_key"]
