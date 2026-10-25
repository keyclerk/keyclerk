"""The signed change log's two wire formats (decision 0022): a change link and a checkpoint.

Both are sealed the way amendment 0014d seals every signed object: they carry the exact bytes that were signed, so no
verifier in any language rebuilds canonical JSON. canonical() only produces the bytes; a verifier checks the signature
over the label and the decoded bytes, then parses them (canonical, no floats, no duplicate keys, edge._parse).

    sealed     = {"bytes": base64(body bytes), "signature": hex of 64 bytes}
    message    = label + "\\n" + body bytes                    label: kc-change-link-v1 or kc-checkpoint-v1
    signature  = Ed25519 over the message, by the records key
    link hash  = SHA-256(0x00 || message || signature bytes)   the RFC 6962 leaf hash (merkle.leaf); prev names it

kc-change-link-v1 body: {"format", "realm", "seq" (leaf index, 0 is the genesis), "prev" (the link hash of seq-1 in hex,
64 zeros for the genesis), "fence" (fencing number, never lower than the link before, so a signer that lost its lease
cannot extend the chain), "at" (UTC time), "change": {"ops": [...], "entry": {...}, "yaml": {...} (the genesis only),
"migrate": {...} (seq 1 to k only)}}. An op is {"op": "put", "kind", "key", "record"} or {"op": "del", "kind", "key"},
sorted by (kind, key), one per key.

Migration from a signed YAML store (S2; the genesis checks the YAML revision's signature, not only its hash): the
genesis carries "yaml": {"revision", "sha256", "signature", "parts": k}, the exact records.yaml bytes' hash and their
detached signature by the records key, and how many migrate links follow; links 1 to k carry "migrate": {"part": seq,
"parts": k} and put ops only. A log whose genesis names no YAML revision has k = 0 and never a migrate link. A store
refuses every other link until link k, and refuses link k unless the state then equals the signed YAML by meaning
(keyclerk.store.replay.prove_migration).

kc-checkpoint-v1 body: {"format", "realm", "size" (links in the log), "root" (merkle root, hex), "head" (the link hash
of seq size-1, hex), "fence", "at"}.

Not in the log, ever: visits, their events and badges, and the broker's tokens behind approval and proposal proofs.
They are personal data erased after their retention (decision 0022 point 3); the store keeps them in its side
table. A proof enters the log by the hash of its token only.
"""
from __future__ import annotations

import base64
import hashlib
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from keyclerk import records as R
from keyclerk.store import merkle

LINK_FORMAT = "kc-change-link-v1"
CHECKPOINT_FORMAT = "kc-checkpoint-v1"
MAX_LINK = 1024 * 1024                      # bytes of one link's body
ZERO = "0" * 64

SIDE_KINDS = ("visits", "visit_events", "badges", "proof_tokens", "genesis_yaml",    # not in the log
              "anchor_map", "anchor_idp")                                          # decision 0028: the mapping, erasable
PROOF_KINDS = ("approval_proofs", "proposal_proofs")
HEAD_FIELDS = ("realm", "home", "connected_organisations", "root", "retired_places", "situation_feeds")
LOG_KINDS = {**{k: v for k, v in R.KINDS.items() if k not in SIDE_KINDS},
             "persons": "person", "places": "place_id", "org_units": "org_id", "zones": "zone_id",
             **{k: "sha256" for k in PROOF_KINDS}, "head": None}

KEY = re.compile(r"[!-~]{1,256}")
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX128 = re.compile(r"[0-9a-f]{128}")


def _count(v, low: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= low


class StoreRefused(ValueError):
    """The store will not take this: the reason says why."""


def record_key(kind: str, rec) -> str:
    """The key a record is stored under in its kind; a head field is keyed by its name, not by its value."""
    if kind not in LOG_KINDS or kind == "head":
        raise StoreRefused(f"{kind}: no key from a record (not a log kind, or a head field)")
    if not isinstance(rec, dict):
        raise StoreRefused(f"{kind}: a record is an object")
    if kind == "admin_revocations":
        return f"{rec.get('id')}.{rec.get('mode')}"
    v = rec.get(LOG_KINDS[kind])
    if not isinstance(v, str):
        raise StoreRefused(f"{kind}: the record has no {LOG_KINDS[kind]}")
    return v


def proof_record(p: dict) -> dict:
    """A proof as the log carries it: what it covers, who gave it, and the hash of the broker's token (Desk._public)."""
    return {"records": p["records"], "by": p["by"], "sha256": hashlib.sha256(str(p.get("token", "")).encode()).hexdigest()}


def _ops(ops) -> list[dict]:
    if not isinstance(ops, list):
        raise StoreRefused("change.ops is a list")
    seen = []
    for op in ops:
        if not isinstance(op, dict) or op.get("op") not in ("put", "del"):
            raise StoreRefused("an op is put or del")
        if set(op) != ({"op", "kind", "key", "record"} if op["op"] == "put" else {"op", "kind", "key"}):
            raise StoreRefused(f"a {op['op']} op has exactly its fields")
        kind, key = op["kind"], op["key"]
        if kind in SIDE_KINDS:
            raise StoreRefused(f"{kind}: personal data kept outside the log, never in a link")
        if kind not in LOG_KINDS:
            raise StoreRefused(f"{str(kind)[:40]}: not a kind of record")
        if not isinstance(key, str) or not KEY.fullmatch(key):
            raise StoreRefused(f"{kind}: a key is 1 to 256 printable ASCII characters")
        if kind == "head":
            if key not in HEAD_FIELDS:
                raise StoreRefused(f"head {key}: not a head field")
            if op["op"] == "put" and (not isinstance(op["record"], dict) or set(op["record"]) != {"value"}):
                raise StoreRefused(f"head {key}: the record is {{\"value\": ...}}")
        elif op["op"] == "put":
            if kind in PROOF_KINDS and set(op["record"] if isinstance(op["record"], dict) else ()) != {"records", "by", "sha256"}:
                raise StoreRefused(f"{kind}: a proof enters the log as records, by and the token's sha256, never the token")
            if record_key(kind, op["record"]) != key:
                raise StoreRefused(f"{kind} {key}: the key is not the record's own")
        seen.append((kind, key))
    if seen != sorted(set(seen)):
        raise StoreRefused("ops are sorted by kind and key, one op per key")
    return ops


def _body(body: dict) -> dict:
    """The structure of a link body (the signature is already checked)."""
    if set(body) != {"format", "realm", "seq", "prev", "fence", "at", "change"} or body["format"] != LINK_FORMAT:
        raise StoreRefused(f"not a {LINK_FORMAT} body")
    if not isinstance(body["realm"], str) or not isinstance(body["seq"], int) or isinstance(body["seq"], bool):
        raise StoreRefused("realm is text and seq a whole number")
    if not isinstance(body["fence"], int) or isinstance(body["fence"], bool) or body["fence"] < 1:
        raise StoreRefused("fence is a whole number from 1")
    if not isinstance(body["prev"], str) or not HEX64.fullmatch(body["prev"]):
        raise StoreRefused("prev is 64 lower-case hex characters")
    if not isinstance(body["at"], str) or not E.TIME.fullmatch(body["at"]):
        raise StoreRefused("at is a UTC time, YYYY-MM-DDTHH:MM:SSZ")
    ch = body["change"]
    if not isinstance(ch, dict) or not {"ops", "entry"} <= set(ch) <= {"ops", "entry", "yaml", "migrate"}:
        raise StoreRefused("change has ops and entry (and yaml in the genesis, migrate in a migrate link)")
    if not isinstance(ch["entry"], dict):
        raise StoreRefused("change.entry is an object")
    if "yaml" in ch:
        y = ch["yaml"]
        if body["seq"] != 0:
            raise StoreRefused("only the genesis names the YAML revision it starts from")
        base = {"revision", "sha256", "signature", "parts"}
        if not isinstance(y, dict) or set(y) not in (base, base | {"rekeyed"}) \
                or not _count(y["revision"], 0) or not _count(y["parts"], 1) \
                or ("rekeyed" in y and not _count(y["rekeyed"], 0)) \
                or not isinstance(y["sha256"], str) or not HEX64.fullmatch(y["sha256"]) \
                or not isinstance(y["signature"], str) or not HEX128.fullmatch(y["signature"]):
            raise StoreRefused("yaml is {revision, sha256, signature, parts, rekeyed?}: whole numbers, hex, at least one "
                               "part (rekeyed: how many anchors the migration re-keyed, decision 0028)")
    if "migrate" in ch:
        m = ch["migrate"]
        if not isinstance(m, dict) or set(m) != {"part", "parts"} or not _count(m["part"], 1) \
                or not _count(m["parts"], 1) or m["part"] != body["seq"] or m["part"] > m["parts"]:
            raise StoreRefused("migrate is {part, parts}, part = seq, from 1 to parts")
        if any(op["op"] != "put" for op in ch["ops"] if isinstance(op, dict)):
            raise StoreRefused("a migrate link only puts records")
    _ops(ch["ops"])
    return body


def _message(label: str, raw: bytes) -> bytes:
    return label.encode("ascii") + b"\n" + raw


def _seal(key: Ed25519PrivateKey, label: str, body: dict) -> dict:
    raw = E.canonical(body)
    return {"bytes": base64.b64encode(raw).decode("ascii"), "signature": key.sign(_message(label, raw)).hex()}


def _open(sealed, pinned: str, label: str) -> tuple[bytes, dict]:
    """(message || signature, the parsed body): the signature checked first, over the bytes as they came."""
    if not isinstance(sealed, dict) or set(sealed) != {"bytes", "signature"}:
        raise StoreRefused(f"a sealed {label} is exactly bytes and signature")
    try:
        raw = E._raw(sealed["bytes"])
    except ValueError as e:
        raise StoreRefused(str(e)) from None
    if len(raw) > MAX_LINK:
        raise StoreRefused(f"a {label} body is at most {MAX_LINK} bytes")
    msg = _message(label, raw)
    if not E._verifies(pinned, sealed["signature"], msg):
        raise StoreRefused(f"the {label} is not signed by the records key")
    try:
        body = E._parse(raw)
    except ValueError as e:
        raise StoreRefused(str(e)) from None
    return msg + bytes.fromhex(sealed["signature"]), body


# --- links ------------------------------------------------------------------------------------------------------------

def link_body(realm: str, seq: int, prev: str, fence: int, at: str, ops: list[dict], entry: dict,
              yaml: dict | None = None, migrate: dict | None = None) -> dict:
    """An unsigned link body, its structure checked: what a signer checks a change as before it signs anything."""
    change = {"ops": sorted(ops, key=lambda o: (o["kind"], o["key"])), "entry": entry, **({"yaml": yaml} if yaml else {}),
              **({"migrate": migrate} if migrate else {})}
    body = _body({"format": LINK_FORMAT, "realm": realm, "seq": seq, "prev": prev, "fence": fence, "at": at,
                  "change": change})
    E.canonical(body)                             # refuses floats and out-of-range integers now, not at signing
    return body


def seal_body(key: Ed25519PrivateKey, body: dict) -> dict:
    return _seal(key, LINK_FORMAT, _body(body))


def seal_link(key: Ed25519PrivateKey, realm: str, seq: int, prev: str, fence: int, at: str, ops: list[dict],
              entry: dict, yaml: dict | None = None, migrate: dict | None = None) -> dict:
    return seal_body(key, link_body(realm, seq, prev, fence, at, ops, entry, yaml, migrate))


def open_link(sealed, pinned: str) -> tuple[dict, bytes]:
    """(the body, the link hash) of a link signed by the pinned key, or StoreRefused; no chain context."""
    data, body = _open(sealed, pinned, LINK_FORMAT)
    return _body(body), merkle.leaf(data)


def check_next(sealed, pinned: str, realm: str, size: int, head: bytes | None, fence: int) -> tuple[dict, bytes]:
    """A link that may follow a log of `size` links whose last hash is `head` and last fence `fence`."""
    body, h = open_link(sealed, pinned)
    return follows(body, realm, size, head, fence), h


def follows(body: dict, realm: str, size: int, head: bytes | None, fence: int) -> dict:
    """A link body, signed or not yet, that may follow a log of `size` links ending in `head` at fence `fence`."""
    if body["realm"] != realm:
        raise StoreRefused(f"a link of realm {body['realm'][:40]}, not {realm}")
    if body["seq"] != size:
        raise StoreRefused(f"link {body['seq']} where link {size} comes next")
    if body["prev"] != (head.hex() if head is not None else ZERO):
        raise StoreRefused(f"link {size} does not follow the head: its prev names another link")
    if body["fence"] < fence:
        raise StoreRefused(f"link {size} has fence {body['fence']} after fence {fence}: a signer that lost its lease")
    return body


def parts(genesis: dict) -> int:
    """k: how many migrate links follow this genesis (0 for a log that starts empty)."""
    y = genesis["change"].get("yaml")
    return y["parts"] if y else 0


def check_migrate(body: dict, k: int) -> None:
    """Links 1 to k are the migration and nothing else; no link after k is one (decision 0022 S2: no bulk path around approvals, point 4)."""
    m, seq = body["change"].get("migrate"), body["seq"]
    if 1 <= seq <= k and (m is None or m["parts"] != k):
        raise StoreRefused(f"link {seq} of a log still migrating ({k} parts): only migrate part {seq} of {k} comes next")
    if seq > k and m is not None:
        raise StoreRefused(f"link {seq} is a migrate link, but the migration ended at link {k}: no bulk path past approvals")


# --- checkpoints ------------------------------------------------------------------------------------------------------

def seal_checkpoint(key: Ed25519PrivateKey, realm: str, size: int, root: bytes, head: bytes, fence: int, at: str) -> dict:
    return _seal(key, CHECKPOINT_FORMAT, {"format": CHECKPOINT_FORMAT, "realm": realm, "size": size, "root": root.hex(),
                                          "head": head.hex(), "fence": fence, "at": at})


def open_checkpoint(sealed, pinned: str) -> dict:
    _, body = _open(sealed, pinned, CHECKPOINT_FORMAT)
    if set(body) != {"format", "realm", "size", "root", "head", "fence", "at"} or body["format"] != CHECKPOINT_FORMAT:
        raise StoreRefused(f"not a {CHECKPOINT_FORMAT} body")
    if not isinstance(body["size"], int) or isinstance(body["size"], bool) or body["size"] < 1:
        raise StoreRefused("a checkpoint covers at least one link")
    if not all(isinstance(body[k], str) and HEX64.fullmatch(body[k]) for k in ("root", "head")):
        raise StoreRefused("root and head are 64 lower-case hex characters")
    if not isinstance(body["fence"], int) or isinstance(body["fence"], bool) or body["fence"] < 1:
        raise StoreRefused("fence is a whole number from 1")
    if not isinstance(body["at"], str) or not E.TIME.fullmatch(body["at"]):
        raise StoreRefused("at is a UTC time, YYYY-MM-DDTHH:MM:SSZ")
    return body


def check_checkpoint(sealed, pinned: str, realm: str, size: int, root: bytes, head: bytes | None) -> dict:
    """A checkpoint that states exactly this log: its realm, size, root and head."""
    body = open_checkpoint(sealed, pinned)
    if body["realm"] != realm:
        raise StoreRefused(f"a checkpoint of realm {body['realm'][:40]}, not {realm}")
    if body["size"] != size:
        raise StoreRefused(f"a checkpoint of {body['size']} links, but the log holds {size}")
    if head is None or body["root"] != root.hex() or body["head"] != head.hex():
        raise StoreRefused(f"the checkpoint's root or head is not this log's at {size} links")
    return body
