# SPDX-License-Identifier: EUPL-1.2
"""Trustee keys: the root of trust for what the records key may not decide alone (#41; review
docs/reviews/2026-11-06-41-rotation-adversarial-review.md, decisions D1 to D3).

A trustee is a security officer or a root trust owner with a signing key on their own hardware, never on a KeyClerk
host. Every verifier pins a trustee set in its own configuration, apart from the records key, so whoever holds the
records key cannot write themselves in. The set changes only by its own threshold.

    set  kc-trustees-v1 = {"format", "realm", "version", "trustees": [{"trustee_id", "anchor", "role": officer | root,
                           "key": {"type", "public_key"}}], "at"}
    key types           sk-ssh-ed25519   a FIDO2 key; signatures are SSHSIG with user presence (ssh-keygen -Y sign)
                        ssh-ed25519      a smartcard through an SSH agent (OpenPGP card, PIV); signatures are SSHSIG
                        ed25519          a raw Ed25519 key (a PIV card); signatures are raw Ed25519
    a signature         {"trustee_id", "sig"}: over label + "\\n" + the statement's bytes; SSHSIG in namespace
                        keyclerk-trustee@<realm>, armored or base64
    the threshold       one officer and one root trust owner, two different people
    a set               at least two officers and two root trust owners; nobody in both roles
    the next set        version + 1, signed under kc-trustees-v1 by the current set's threshold, and each key new to it
                        signs the same bytes under kc-trustees-accept-v1 (possession)

    python -m keyclerk.trustees check SET.json                     is the set well formed
    python -m keyclerk.trustees statement LABEL FILE               the bytes to sign (written to FILE.tosign)
    python -m keyclerk.trustees verify SET.json LABEL FILE SIG...  does a threshold of the set sign FILE under LABEL
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FORMAT = "kc-trustees-v1"
ACCEPT = "kc-trustees-accept-v1"
KEY_TYPES = ("sk-ssh-ed25519", "ssh-ed25519", "ed25519")
ROLES = ("officer", "root")
MAX_TRUSTEES = 20
MAX_SIG = 16 * 1024
_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SK_PREFIX = "sk-ssh-ed25519" + "@" + "openssh.com"
UP = 0x01                                       # the authenticator's user-presence flag


class TrusteeRefused(ValueError):
    """A set or a signature that does not hold, with why."""


# --- SSH wire format ----------------------------------------------------------------------------------------------

def _read(buf: bytes, i: int) -> tuple[bytes, int]:
    if i + 4 > len(buf):
        raise TrusteeRefused("an SSH string runs past the end")
    n = struct.unpack(">I", buf[i:i + 4])[0]
    if i + 4 + n > len(buf):
        raise TrusteeRefused("an SSH string runs past the end")
    return buf[i + 4:i + 4 + n], i + 4 + n


def _string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _pubkey(blob: bytes) -> tuple[str, bytes, bytes | None]:
    """(type, raw 32-byte key, application or None) of an SSH public key blob."""
    t, i = _read(blob, 0)
    raw, i = _read(blob, i)
    app = None
    if t == _SK_PREFIX.encode():
        app, i = _read(blob, i)
    elif t != b"ssh-ed25519":
        raise TrusteeRefused(f"key type {t[:40]!r} is not ssh-ed25519 or {_SK_PREFIX}")
    if i != len(blob) or len(raw) != 32:
        raise TrusteeRefused("a malformed SSH Ed25519 key")
    return t.decode(), raw, app


def public_key_of(text: str) -> dict:
    """{"type", "public_key"} from an OpenSSH public key line, or from a raw key in hex."""
    text = text.strip()
    if re.fullmatch(r"[0-9a-f]{64}", text):
        return {"type": "ed25519", "public_key": text}
    parts = text.split()
    if len(parts) < 2 or parts[0] not in ("ssh-ed25519", _SK_PREFIX):
        raise TrusteeRefused("an OpenSSH ssh-ed25519 or sk-ssh-ed25519 public key, or 64 hex characters")
    blob = base64.b64decode(parts[1], validate=True)
    t, _, _ = _pubkey(blob)
    if t != parts[0]:
        raise TrusteeRefused("the key line's type and its blob differ")
    return {"type": "sk-ssh-ed25519" if t == _SK_PREFIX else "ssh-ed25519",
            "public_key": base64.b64encode(blob).decode()}


def _sshsig_blob(sig: str) -> bytes:
    s = sig.strip()
    if s.startswith("-----BEGIN SSH SIGNATURE-----"):
        body = s.split("-----BEGIN SSH SIGNATURE-----", 1)[1].split("-----END SSH SIGNATURE-----", 1)[0]
        s = "".join(body.split())
    try:
        blob = base64.b64decode(s, validate=True)
    except ValueError:
        raise TrusteeRefused("an SSH signature that does not decode") from None
    if not blob.startswith(b"SSHSIG"):
        raise TrusteeRefused("not an SSHSIG signature")
    return blob


def _verify_sshsig(key: dict, sig: str, namespace: str, message: bytes) -> None:
    """OpenSSH's PROTOCOL.sshsig, for ssh-ed25519 and sk-ssh-ed25519 (user presence required)."""
    blob = _sshsig_blob(sig)
    i = 6
    if len(blob) < 10 or struct.unpack(">I", blob[i:i + 4])[0] != 1:
        raise TrusteeRefused("SSHSIG version 1 only")
    i += 4
    pub, i = _read(blob, i)
    ns, i = _read(blob, i)
    reserved, i = _read(blob, i)
    alg, i = _read(blob, i)
    sigblob, i = _read(blob, i)
    if i != len(blob):
        raise TrusteeRefused("trailing bytes after the SSH signature")
    if reserved:                                 # N10: OpenSSH writes it empty; nothing else is signed in it
        raise TrusteeRefused("the SSH signature's reserved field is not empty")
    if pub != base64.b64decode(key["public_key"]):
        raise TrusteeRefused("signed by another key than the trustee's")
    if ns != namespace.encode():
        raise TrusteeRefused(f"signed in namespace {ns[:60]!r}, not {namespace}")
    if alg not in (b"sha256", b"sha512"):
        raise TrusteeRefused("SSHSIG hash sha256 or sha512 only")
    h = hashlib.sha256(message).digest() if alg == b"sha256" else hashlib.sha512(message).digest()
    signed = b"SSHSIG" + _string(ns) + _string(reserved) + _string(alg) + _string(h)
    t, raw, app = _pubkey(pub)
    st, j = _read(sigblob, 0)
    sig64, j = _read(sigblob, j)
    if st.decode(errors="replace") != t or len(sig64) != 64:
        raise TrusteeRefused("the signature's type is not the key's")
    if app is not None:                          # FIDO2: the authenticator signs its own envelope
        if j + 5 != len(sigblob):
            raise TrusteeRefused("a malformed sk signature")
        flags, counter = sigblob[j], sigblob[j + 1:j + 5]
        if not flags & UP:
            raise TrusteeRefused("the FIDO2 key signed without user presence")
        signed = hashlib.sha256(app).digest() + bytes([flags]) + counter + hashlib.sha256(signed).digest()
    elif j != len(sigblob):
        raise TrusteeRefused("trailing bytes in the signature")
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(sig64, signed)
    except InvalidSignature:
        raise TrusteeRefused("the signature does not verify") from None


def verify(trustee: dict, realm: str, label: str, statement: bytes, sig: str) -> None:
    """The trustee's signature over label + "\\n" + statement, or TrusteeRefused."""
    if not isinstance(sig, str) or len(sig) > MAX_SIG:
        raise TrusteeRefused("a signature is text of a sane size")
    message = label.encode() + b"\n" + statement
    key = trustee["key"]
    if key["type"] == "ed25519":
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key["public_key"])).verify(bytes.fromhex(sig), message)
        except (ValueError, InvalidSignature):
            raise TrusteeRefused("the signature does not verify") from None
        return
    _verify_sshsig(key, sig, f"keyclerk-trustee@{realm}", message)


# --- sets and thresholds ------------------------------------------------------------------------------------------

def check(ts: dict) -> list[str]:
    """Why this trustee set may not be pinned; [] when it may."""
    errs = []
    if not isinstance(ts, dict) or ts.get("format") != FORMAT:
        return [f"not a {FORMAT} set"]
    if set(ts) != {"format", "realm", "version", "trustees", "at"}:
        errs.append("a set is {format, realm, version, trustees, at}")
    if not isinstance(ts.get("version"), int) or isinstance(ts.get("version"), bool) or ts["version"] < 1:
        errs.append("version is a whole number from 1")
    people = ts.get("trustees")
    if not isinstance(people, list) or not 4 <= len(people) <= MAX_TRUSTEES:
        return errs + [f"four to {MAX_TRUSTEES} trustees: at least two officers and two root trust owners"]
    ids, keys, roles = set(), set(), {}
    for t in people:
        if not isinstance(t, dict) or set(t) != {"trustee_id", "anchor", "role", "key"}:
            errs.append("a trustee is {trustee_id, anchor, role, key}")
            continue
        tid = t["trustee_id"]
        if not isinstance(tid, str) or not _ID.match(tid) or tid in ids:
            errs.append(f"trustee id {str(tid)[:40]!r}: lower-case letters, digits, - and _, once each")
            continue                             # N10: a malformed set is refused with reasons, never a TypeError
        ids.add(tid)
        if not isinstance(t["role"], str) or t["role"] not in ROLES:
            errs.append(f"{tid}: role is officer or root")
            continue
        if not isinstance(t["anchor"], str) or not t["anchor"]:
            errs.append(f"{tid}: anchor is a person's internal anchor")
            continue
        roles.setdefault(t["anchor"], set()).add(t["role"])
        k = t["key"]
        if not isinstance(k, dict) or set(k) != {"type", "public_key"} or k.get("type") not in KEY_TYPES \
                or not isinstance(k.get("public_key"), str):
            errs.append(f"{tid}: key is {{type: {', '.join(KEY_TYPES)}, public_key}}")
            continue
        try:
            if k["type"] == "ed25519":
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(k["public_key"]))
            else:
                t2, _, app = _pubkey(base64.b64decode(k["public_key"], validate=True))
                if (t2 == _SK_PREFIX) != (k["type"] == "sk-ssh-ed25519"):
                    raise TrusteeRefused("type and blob differ")
        except (ValueError, TrusteeRefused) as e:
            errs.append(f"{tid}: the key does not decode ({str(e)[:80]})")
        if k["public_key"] in keys:
            errs.append(f"{tid}: a key held by another trustee too")
        keys.add(k["public_key"])
    for anchor, rs in roles.items():
        if len(rs) > 1:
            errs.append(f"{anchor}: one person is never both officer and root trustee")
    for role in ROLES:
        if sum(1 for t in people if isinstance(t, dict) and t.get("role") == role) < 2:
            errs.append(f"at least two {role} trustees, so one who leaves or is compromised can be replaced")
    return errs


def threshold(ts: dict, label: str, statement: bytes, sigs: list[dict]) -> list[str]:
    """The trustee ids whose signatures hold, when they make one officer and one root trust owner, two different
    people; TrusteeRefused otherwise, saying what is missing."""
    by_id = {t["trustee_id"]: t for t in ts["trustees"]}
    good, why = [], []
    for s in sigs or []:
        t = by_id.get((s or {}).get("trustee_id")) if isinstance(s, dict) else None
        if t is None:
            why.append("a signature by no trustee of the pinned set")
            continue
        try:
            verify(t, ts["realm"], label, statement, s.get("sig"))
        except TrusteeRefused as e:
            why.append(f"{t['trustee_id']}: {e}")
            continue
        good.append(t)
    for o in (t for t in good if t["role"] == "officer"):
        for r in (t for t in good if t["role"] == "root"):
            if o["anchor"] != r["anchor"]:
                return sorted({o["trustee_id"], r["trustee_id"]})
    raise TrusteeRefused("needs one officer and one root trust owner of the pinned set, two people"
                         + (f" ({'; '.join(why[:4])})" if why else ""))


def canonical(ts: dict) -> bytes:
    return json.dumps(ts, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def next_set(current: dict, proposed: dict, sigs: list[dict], accepts: list[dict]) -> dict:
    """The proposed set, once it may replace the pinned one: well formed, the same realm, version + 1, signed by the
    current threshold, and every key new to it proving possession; TrusteeRefused otherwise."""
    errs = check(proposed)
    if errs:
        raise TrusteeRefused("; ".join(errs[:4]))
    if proposed["realm"] != current["realm"]:
        raise TrusteeRefused("a set for another realm")
    if proposed["version"] != current["version"] + 1:
        raise TrusteeRefused(f"version {proposed['version']} does not follow {current['version']}: never skipped")
    body = canonical(proposed)
    threshold(current, FORMAT, body, sigs)
    old = {t["key"]["public_key"] for t in current["trustees"]}
    proofs = {(a or {}).get("trustee_id"): (a or {}).get("sig") for a in accepts or [] if isinstance(a, dict)}
    for t in proposed["trustees"]:
        if t["key"]["public_key"] in old:
            continue
        if t["trustee_id"] not in proofs:
            raise TrusteeRefused(f"{t['trustee_id']}: a new key proves possession (signs under {ACCEPT})")
        verify(t, proposed["realm"], ACCEPT, body, proofs[t["trustee_id"]])
    return proposed


_PIN: dict = {}
_USE: dict = {}


def use(ts: dict | None, since: int = 0) -> None:
    """Pin a trustee set in this process without KeyClerk's configuration (the commit witness's --trustees). The pin is
    the process's: another set is refused while one is pinned (N10), so a second witness in the same process cannot
    swap the first one's trustees; use(None) clears it."""
    if ts is not None:
        errs = check(ts)
        if errs:
            raise TrusteeRefused("the trustee set is not well formed: " + "; ".join(errs[:3]))
        held = _USE.get("value")
        if held is not None and (canonical(held["set"]) != canonical(ts) or held["since"] != int(since)):
            raise TrusteeRefused("this process already pins another trustee set: one set per process")
    _USE.clear()
    if ts is not None:
        _USE["value"] = {"set": ts, "since": int(since)}


def pinned() -> dict | None:
    """{"set", "since"} from this process's configuration (trustees: {set: FILE, since: N}), or None when it pins none.
    From link `since` on, an HA change link or a restore link counts only with a threshold of this set (F1)."""
    from keyclerk import config
    if _USE:
        return _USE["value"]
    try:
        cfg = config.current().get("trustees")
    except RuntimeError:                        # no configuration: a library use, nothing pinned
        return None
    if not cfg:
        return None
    path = Path(cfg["set"])
    stamp = (str(path), path.stat().st_mtime_ns, int(cfg.get("since", 0)))
    if _PIN.get("stamp") != stamp:
        ts = json.loads(path.read_text(encoding="utf-8"))
        errs = check(ts)
        if errs:
            raise TrusteeRefused(f"the pinned trustee set {path} is not well formed: " + "; ".join(errs[:3]))
        _PIN.update(stamp=stamp, value={"set": ts, "since": stamp[2]})
    return _PIN["value"]


def main(argv: list[str]) -> int:
    if argv and argv[0] == "next":                # N10: the next set, verified before it is written
        try:
            cur, prop, sigs, accepts, out = (Path(x) for x in argv[1:6])
            nxt = next_set(json.loads(cur.read_text(encoding="utf-8")), json.loads(prop.read_text(encoding="utf-8")),
                           json.loads(sigs.read_text(encoding="utf-8")), json.loads(accepts.read_text(encoding="utf-8")))
        except (TrusteeRefused, OSError, ValueError, TypeError) as e:
            print(f"refused: {e}", file=sys.stderr)
            return 1
        tmp = out.with_name(out.name + ".tmp")
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(nxt, indent=1, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, out)
        print(f"version {nxt['version']} verified against version {nxt['version'] - 1}: pin {out} where the old set "
              "was (configuration trustees.set, the commit witness's --trustees)")
        return 0
    if not argv or argv[0] not in ("check", "statement", "verify"):
        print(__doc__.strip().splitlines()[-3].strip(), file=sys.stderr)
        return 2
    try:
        if argv[0] == "check":
            errs = check(json.loads(Path(argv[1]).read_text(encoding="utf-8")))
            for e in errs:
                print(e, file=sys.stderr)
            return 1 if errs else 0
        if argv[0] == "statement":
            src = Path(argv[2])
            Path(str(src) + ".tosign").write_bytes(argv[1].encode() + b"\n" + src.read_bytes())
            print(f"sign {src}.tosign: ssh-keygen -Y sign -n keyclerk-trustee@<realm> -f <your key> {src}.tosign")
            return 0
        ts = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        sigs = [json.loads(Path(p).read_text(encoding="utf-8")) for p in argv[4:]]
        print("signed by " + ", ".join(threshold(ts, argv[2], Path(argv[3]).read_bytes(), sigs)))
        return 0
    except (TrusteeRefused, OSError, ValueError, IndexError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
