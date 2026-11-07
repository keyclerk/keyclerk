# SPDX-License-Identifier: EUPL-1.2
"""The records-key history: which key, under which log origin, signs which links (#41; review
docs/reviews/2026-11-06-41-rotation-adversarial-review.md, design points 2 and 3, decisions D3 and D4).

The records key is an online key the trustees certify; it never names its successor. A history is a document the
trustees sign, versioned N to N+1; planned rotation and recovery after a compromise are the same step, a recovery
only switching earlier. Every consumer pins the trustee set and a history version out of band, then accepts newer
versions on their signatures alone, from whatever source they arrive.

    kc-records-keys-v1 = {"format", "realm", "version", "keys": [{"key", "origin", "from_seq", "to_seq"}],
                          "trusted": {"note", "witness"} or null, "reason_sha256", "at"}
    sealed             = {"bytes": base64(canonical body), "trustees": [{"trustee_id", "sig"}, ...],
                          "accept": {"key", "sig"} or null}

- The windows are contiguous from link 0: the first starts at 0, each ends where the next starts, only the last is open
  (to_seq null). A key and an origin appear once each: a new key is a new log origin (D3), so a C2SP witness pinned to
  the old origin simply stops.
- A link at seq n is signed by the key whose window holds n; a checkpoint of size s by the key that signed link s-1, so
  the old key closes its own era and the witness's countersignature on that checkpoint certifies the switch.
- Version N+1: signed under kc-records-keys-v1 by one officer and one root trust owner of the pinned trustee set; its
  last key, when new, proves possession under kc-records-keys-accept-v1 (raw Ed25519); its other windows equal
  version N's clipped at the switch point b (the last key's from_seq), entries from b on dropped; b is after the start
  of version N's last key, so no switch ever reaches back into a retired key's era; and `trusted` is a checkpoint note
  of size b, signed by the key in force at b - 1 under its origin and countersigned by the named witness.
- A consumer that held links from b on signed by an older key drops them (they are the compromised key's) and keeps
  them as evidence; from b on only the new key counts.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FORMAT = "kc-records-keys-v1"
ACCEPT = "kc-records-keys-accept-v1"
MAX_KEYS = 64
FIELDS = {"format", "realm", "version", "keys", "trusted", "reason_sha256", "at"}


class HistoryRefused(ValueError):
    """A history that does not hold, with why."""


def canonical(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _whole(v, low: int = 0) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= low


def check(doc: dict) -> list[str]:
    """Why this document is not a well-formed history; [] when it is (its signatures are advance's business)."""
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        return [f"not a {FORMAT} document"]
    errs = []
    if set(doc) != FIELDS:
        errs.append("a history is {" + ", ".join(sorted(FIELDS)) + "}")
    if not _whole(doc.get("version"), 1):
        errs.append("version is a whole number from 1")
    keys = doc.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_KEYS:
        return errs + [f"keys: one to {MAX_KEYS} windows"]
    seen_k, seen_o, at = set(), set(), 0
    for i, w in enumerate(keys):
        last = i == len(keys) - 1
        if not isinstance(w, dict) or set(w) != {"key", "origin", "from_seq", "to_seq"}:
            errs.append(f"window {i}: {{key, origin, from_seq, to_seq}}")
            continue
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(w["key"]))
        except (ValueError, TypeError):
            errs.append(f"window {i}: key is 64 hex characters of an Ed25519 key")
        if not isinstance(w["origin"], str) or not 1 <= len(w["origin"]) <= 200 or " " in w["origin"]:
            errs.append(f"window {i}: origin is a log origin, no spaces")
        if w["from_seq"] != at:
            errs.append(f"window {i} starts at {w['from_seq']}, not {at}: windows are contiguous from link 0")
        if last:
            if w["to_seq"] is not None:
                errs.append("the last window is open (to_seq null)")
        elif not _whole(w["to_seq"]) or w["to_seq"] <= w["from_seq"]:
            errs.append(f"window {i}: to_seq is after from_seq")
        else:
            at = w["to_seq"]
        if w["key"] in seen_k:
            errs.append(f"window {i}: a key is used once")
        if w["origin"] in seen_o:
            errs.append(f"window {i}: an origin is used once: a new key is a new log origin")
        seen_k.add(w["key"])
        seen_o.add(w["origin"])
    t = doc.get("trusted")
    if doc.get("version") == 1 and len(keys) == 1:
        if t is not None:
            errs.append("version 1 with one key rests on no checkpoint (trusted null)")
    elif not isinstance(t, dict) or set(t) != {"note", "witness"} or not all(isinstance(x, str) for x in t.values()):
        errs.append("trusted is {note, witness}: the countersigned checkpoint the switch rests on")
    if not isinstance(doc.get("reason_sha256"), str) or len(doc["reason_sha256"]) != 64:
        errs.append("reason_sha256 is a SHA-256 in hex")
    try:
        datetime.fromisoformat(str(doc.get("at")).replace("Z", "+00:00"))
    except ValueError:
        errs.append("at is a time")
    return errs


class KeyHistory:
    """A checked history, to ask which key and origin are in force for a link or a checkpoint."""

    def __init__(self, doc: dict, chain: list | None = None):
        errs = check(doc)
        if errs:
            raise HistoryRefused("; ".join(errs[:4]))
        self.doc = doc
        self.version = doc["version"]
        self.chain = list(chain or [])            # the sealed versions from an operator's pin to this one (review N1)

    def window(self, seq: int) -> dict:
        for w in self.doc["keys"]:
            if w["from_seq"] <= seq and (w["to_seq"] is None or seq < w["to_seq"]):
                return w
        raise HistoryRefused(f"no key is in force at link {seq}")

    def key_at(self, seq: int) -> str:
        return self.window(seq)["key"]

    def checkpoint_key(self, size: int) -> dict:
        """The window whose key signs a checkpoint of `size` links: the one that signed link size - 1."""
        return self.window(max(size - 1, 0))

    @property
    def switch(self) -> int:
        """Where the newest key took over."""
        return self.doc["keys"][-1]["from_seq"]


def _trusted_note(prev: KeyHistory, doc: dict, b: int, witness_pin: str | None) -> None:
    from keyclerk.store import note as N
    t = doc["trusted"]
    if witness_pin is not None and t["witness"] != witness_pin:
        raise HistoryRefused("the history names another witness than the one this verifier pins")
    try:
        text, sigs = N.split(t["note"])
        origin, size, _ = N.parse_checkpoint(text)
        w = prev.checkpoint_key(size)
        if size != b:
            raise HistoryRefused(f"the trusted checkpoint has size {size}, the switch is at {b}")
        if origin != w["origin"]:
            raise HistoryRefused(f"the trusted checkpoint is of origin {origin[:60]}, not {w['origin'][:60]}")
        if N.verify(text, sigs, (origin, N.LOG, bytes.fromhex(w["key"]))) is None:
            raise HistoryRefused("the trusted checkpoint is not signed by the key in force there")
        if N.verify(text, sigs, N.parse_vkey(t["witness"])) is None:
            raise HistoryRefused("the trusted checkpoint is not countersigned by the named witness")
    except N.NoteRefused as e:
        raise HistoryRefused(f"the trusted checkpoint does not hold: {e}") from None


def advance(prev: KeyHistory, sealed: dict, trustee_set: dict, witness_pin: str | None = None) -> KeyHistory:
    """The next version, once it holds against the pinned one and the pinned trustee set; HistoryRefused otherwise."""
    from keyclerk import trustees as T
    if not isinstance(sealed, dict) or set(sealed) != {"bytes", "trustees", "accept"}:
        raise HistoryRefused("a sealed history is {bytes, trustees, accept}")
    try:
        raw = base64.b64decode(sealed["bytes"], validate=True)
        doc = json.loads(raw)
    except (ValueError, TypeError):
        raise HistoryRefused("the history does not decode") from None
    if canonical(doc) != raw:
        raise HistoryRefused("the history's bytes are not canonical")
    nxt = KeyHistory(doc)
    if doc["realm"] != prev.doc["realm"] or doc["realm"] != trustee_set.get("realm"):
        raise HistoryRefused("a history for another realm")
    if nxt.version != prev.version + 1:
        raise HistoryRefused(f"version {nxt.version} does not follow {prev.version}: never skipped")
    try:
        T.threshold(trustee_set, FORMAT, raw, sealed["trustees"])
    except T.TrusteeRefused as e:
        raise HistoryRefused(f"not signed by the trustees: {e}") from None
    b, new = nxt.switch, doc["keys"][-1]
    if b < max(prev.switch, 1):                   # N10: at the current key's start, it is replaced before its first link
        raise HistoryRefused(f"the switch at {b} is before the current key's start {prev.switch}: no switch reaches "
                             "into a retired key's era")
    want = []
    for w in prev.doc["keys"]:
        if w["from_seq"] >= b:
            continue
        to = b if w["to_seq"] is None else min(w["to_seq"], b)
        want.append({**w, "to_seq": to})
    if doc["keys"][:-1] != want:
        raise HistoryRefused("the earlier windows are not the pinned history's, clipped at the switch")
    used = {w["key"] for w in prev.doc["keys"]}
    for old in prev.chain:                        # a key replaced before its first link leaves the windows, not the past
        try:
            used |= {w["key"] for w in json.loads(base64.b64decode(old["bytes"]))["keys"]}
        except (ValueError, TypeError, KeyError):
            pass
    if new["key"] in used:
        raise HistoryRefused("the new key was in the history before: a key is used once")
    acc = sealed["accept"]
    if not isinstance(acc, dict) or acc.get("key") != new["key"]:
        raise HistoryRefused(f"the new key proves possession (signs under {ACCEPT})")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(new["key"])).verify(
            bytes.fromhex(str(acc.get("sig"))), ACCEPT.encode() + b"\n" + raw)
    except (ValueError, InvalidSignature):
        raise HistoryRefused("the new key's proof of possession does not verify") from None
    _trusted_note(prev, doc, b, witness_pin)
    nxt.chain = prev.chain + [sealed]
    return nxt


def rebuild(pin: KeyHistory | None, chain: list, trustee_set: dict | None, genesis: str) -> KeyHistory | None:
    """The history a verifier may hold (review N1, N2): its operator's pin, moved forward only through sealed versions
    that hold against the pinned trustee set, whatever a state file claims. None when no pin starts from this log's
    genesis key: then nothing beyond that key is trusted. A stored version equal to the pin's must be the pin."""
    if pin is None or pin.key_at(0) != genesis:
        return None
    cur = pin
    for sealed in chain or []:
        try:
            doc = json.loads(base64.b64decode(sealed["bytes"], validate=True))
            v = doc["version"]
        except (ValueError, TypeError, KeyError):
            raise HistoryRefused("a stored records-key version does not decode") from None
        if v < cur.version:
            continue
        if v == cur.version:
            if canonical(doc) != canonical(cur.doc):
                raise HistoryRefused(f"a stored version {v} is not the pinned version {v}: the state was changed")
            continue
        if trustee_set is None:
            break                                 # no trustees pinned: nothing past the pin is trusted
        cur = advance(cur, sealed, trustee_set)
    return cur


_PIN: dict = {}


def pinned() -> KeyHistory | None:
    """The history version this process pins (configuration records_keys: {history: FILE}, delivered out of band like
    the trustee set), or None. A store opened here adopts it when it starts from the store's key and is newer."""
    from keyclerk import config
    try:
        cfg = config.current().get("records_keys")
    except RuntimeError:
        return None
    if not cfg:
        return None
    path = Path(cfg["history"])
    stamp = (str(path), path.stat().st_mtime_ns)
    if _PIN.get("stamp") != stamp:
        _PIN.update(stamp=stamp, value=KeyHistory(json.loads(path.read_text(encoding="utf-8"))))
    return _PIN["value"]


def dropped(prev: KeyHistory, nxt: KeyHistory, held: int) -> range:
    """Link positions a consumer holding `held` links drops on moving to nxt: those from the switch on that an older
    key signed (empty for a planned rotation, which switches after the newest link the old key signed)."""
    return range(nxt.switch, max(held, nxt.switch)) if held > nxt.switch and prev.key_at(nxt.switch) != nxt.key_at(nxt.switch) else range(0)


USAGE = """The rotation ceremony (#41), the signer stopped:

    python -m keyclerk.records_keys statement --signer-state DIR --key OLD.key --config FILE --new-public HEX
        --origin NEW_ORIGIN --note CHECKPOINT_NOTE --witness VKEY --reason TEXT --out NEXT
            writes NEXT.json (the next history), NEXT.tosign (what two trustees sign: ssh-keygen -Y sign -n
            keyclerk-trustee@REALM, or raw Ed25519) and NEXT.accept (what the new key signs)
    python -m keyclerk.records_keys seal --history NEXT.json --trustee-sig ID=SIGFILE --trustee-sig ID=SIGFILE
        --new-key NEW.key --out SEALED.json [--pinned CURRENT.json --trustees SET.json]
            the sealed version; with --pinned and --trustees it is verified before it is written
    python -m keyclerk.records_keys verify --pinned CURRENT.json --trustees SET.json --sealed SEALED.json [--witness VKEY]
            whether the sealed version follows the pinned one
    python -m keyclerk.records_keys rotate --signer-state DIR --key OLD.key --new-key NEW.key --config FILE
        --sealed SEALED.json
            the signer moves to the new key; start it again with NEW.key
"""


def _read_key(path: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from keyclerk import guard
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(guard.read_bounded(Path(path), 200).strip()))


def _sealed(raw: bytes, sigs: list[dict], new_key) -> dict:
    return {"bytes": base64.b64encode(raw).decode(), "trustees": sigs,
            "accept": {"key": new_key.public_key().public_bytes_raw().hex(),
                       "sig": new_key.sign(ACCEPT.encode() + b"\n" + raw).hex()}}


def _write(path: Path, data: bytes) -> None:
    import os
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def main(argv: list[str]) -> int:
    import argparse
    import sys
    ap = argparse.ArgumentParser(prog="keyclerk.records_keys", description=USAGE,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("statement")
    for a in ("--signer-state", "--key", "--config", "--new-public", "--origin", "--note", "--witness", "--reason", "--out"):
        st.add_argument(a, required=True)
    se = sub.add_parser("seal")
    se.add_argument("--history", required=True)
    se.add_argument("--trustee-sig", action="append", default=[], required=True)
    se.add_argument("--new-key", required=True)
    se.add_argument("--out", required=True)
    se.add_argument("--pinned")
    se.add_argument("--trustees")
    ve = sub.add_parser("verify")
    for a in ("--pinned", "--trustees", "--sealed"):
        ve.add_argument(a, required=True)
    ve.add_argument("--witness")
    ro = sub.add_parser("rotate")
    ro.add_argument("--custodian-token", help="the custodian's token file, over TCP")
    ro.add_argument("--custodian", help="the custodian's socket instead of --key: the old key signs its last line there, "
                                        "then rotate the custodian (keyclerk-custodian rotate) before the signer starts")
    ro.add_argument("--key", help="the old records key, where the signer holds it itself (development and tests)")
    for a in ("--signer-state", "--new-key", "--config", "--sealed"):
        ro.add_argument(a, required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd in ("statement", "rotate"):
            from keyclerk import config
            from keyclerk.signer import Signer, SignerRefused
            config.configure(a.config)
            if getattr(a, "custodian", None):             # decision 0033: the old key lives in the custodian
                from keyclerk import guard
                from keyclerk.custodian import CustodianKey
                tok = guard.read_bounded(Path(a.custodian_token), 200).strip() if a.custodian_token else None
                old = CustodianKey(a.custodian, tok)
            elif a.key:
                old = _read_key(a.key)
            else:
                print("refused: give --key OLD.key or --custodian ADDR", file=sys.stderr)
                return 1
            signer = Signer(old, Path(a.signer_state))
            try:
                if signer.broken:
                    print(f"the signer's state is not ready: {signer.broken}", file=sys.stderr)
                    return 1
                if a.cmd == "statement":
                    doc = signer.rotation_statement(a.new_public, a.origin, Path(a.note).read_text(encoding="utf-8"),
                                                    a.witness, a.reason)
                    raw, out = canonical(doc), Path(a.out)
                    _write(out.with_suffix(".json"), raw)
                    _write(out.with_suffix(".tosign"), FORMAT.encode() + b"\n" + raw)
                    _write(out.with_suffix(".accept"), ACCEPT.encode() + b"\n" + raw)
                    print(f"version {doc['version']}: switch at link {doc['keys'][-1]['from_seq']} to origin "
                          f"{a.origin}; two trustees sign {out.with_suffix('.tosign')}: ssh-keygen -Y sign -n "
                          f"keyclerk-trustee@{doc['realm']} -f KEY {out.with_suffix('.tosign')}")
                    return 0
                out = signer.rotate(json.loads(Path(a.sealed).read_text(encoding="utf-8")), _read_key(a.new_key))
                print(json.dumps(out, sort_keys=True))
                if getattr(a, "custodian", None):
                    print(f"now rotate the custodian (keyclerk-custodian rotate --key OLD.key --next NEW.key --origin "
                          f"ORIGIN --from-seq {out.get('switch', 'N')}), which destroys the old key, then start the "
                          "signer again with --custodian", file=sys.stderr)
                else:
                    print("start the signer again with the new key; followers adopt the version from it", file=sys.stderr)
                return 0
            except SignerRefused as e:
                print(f"refused: {e}", file=sys.stderr)
                return 1
            finally:
                signer.close()
        if a.cmd == "seal":
            raw = Path(a.history).read_bytes()
            sigs = []
            for x in a.trustee_sig:
                tid, _, f = x.partition("=")
                sigs.append({"trustee_id": tid, "sig": Path(f).read_text(encoding="utf-8").strip()})
            sealed = _sealed(raw, sigs, _read_key(a.new_key))
            if a.pinned and a.trustees:
                advance(KeyHistory(json.loads(Path(a.pinned).read_text(encoding="utf-8"))), sealed,
                        json.loads(Path(a.trustees).read_text(encoding="utf-8")))
            _write(Path(a.out), json.dumps(sealed, sort_keys=True, indent=1).encode())
            print(f"wrote {a.out}")
            return 0
        nxt = advance(KeyHistory(json.loads(Path(a.pinned).read_text(encoding="utf-8"))),
                      json.loads(Path(a.sealed).read_text(encoding="utf-8")),
                      json.loads(Path(a.trustees).read_text(encoding="utf-8")), a.witness)
        print(f"version {nxt.version} holds: switch at link {nxt.switch}")
        return 0
    except (HistoryRefused, OSError, ValueError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
