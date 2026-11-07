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
"migrate": {...} (seq 1 to k only), "restore": {...} (a restore link only)}}. An op is {"op": "put", "kind", "key", "record"} or {"op": "del", "kind", "key"},
sorted by (kind, key), one per key.

Migration from a signed YAML store (S2; the genesis checks the YAML revision's signature, not only its hash): the
genesis carries "yaml": {"revision", "sha256", "signature", "parts": k}, the exact records.yaml bytes' hash and their
detached signature by the records key, and how many migrate links follow; links 1 to k carry "migrate": {"part": seq,
"parts": k} and put ops only. A log whose genesis names no YAML revision has k = 0 and never a migrate link. A store
refuses every other link until link k, and refuses link k unless the state then equals the signed YAML by meaning
(keyclerk.store.replay.prove_migration).

A restore link (decision 0019 point 5): a signer restored from an older backup whose lost links no follower holds
must not sign at the positions it lost; it appends one link with no ops and "restore": {"mark", "confirmations":
[{"by", "proof"}, {"by", "proof"}]}: the newest revision anyone saw, confirmed by the security officer and a root
trust owner, each proof the SHA-256 of their broker token (the token in the side table, as approval proofs). The
revision of the restore link is mark + 1 and each link after it adds one; a mark below the revision the log has
reached is refused.

An HA change link (decision 0031 points 3 and 10): after the genesis and its migrate links, the `ha` head record is
put or removed only by a link with "ha": {"mode", "confirmations": [{"by", "proof"}, {"by", "proof"}], "node"
(break_glass only)} and that one op: `set` puts the record (HA on, or other nodes or another commit witness), `off`
removes it, `break_glass` removes it when the commit witness is lost and names the one signer node that signs on from
this link's base (seq and prev). The confirmations are the security officer's and a root trust owner's, as a restore
link's (operator 2026-11-05).

Trustee signatures (#41, F1): a restore link and an HA change link may carry "trustees": [{"trustee_id", "sig"}, ...],
two to four signatures by trustees of the set a verifier pins (keyclerk.trustees) over a statement naming the
position: kc-ha-change-v1 {realm, seq, prev, mode, node, value_sha256} or kc-restore-v1 {realm, seq, prev, mark}.
A verifier that pins a set (configuration trustees: {set, since}) refuses such a link at or after `since` without
one officer's and one root trust owner's signatures; the confirmations' token hashes stay, for the signer's own
check, but no verifier can check a hash, so they no longer decide anything there.

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
HEAD_FIELDS = ("realm", "home", "connected_organisations", "root", "retired_places", "situation_feeds", "ha")
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
    if not isinstance(ch, dict) or not {"ops", "entry"} <= set(ch) <= {"ops", "entry", "yaml", "migrate", "restore", "ha"}:
        raise StoreRefused("change has ops and entry (and yaml in the genesis, migrate in a migrate link, restore in a "
                           "restore link, ha in an HA change link)")
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
    if "restore" in ch:
        r = ch["restore"]
        if body["seq"] < 1 or ch["ops"] or "yaml" in ch or "migrate" in ch:
            raise StoreRefused("a restore link follows the genesis and carries no ops")
        if not isinstance(r, dict) or set(r) - {"trustees"} != {"mark", "confirmations"} or not _count(r["mark"], 1) \
                or not isinstance(r["confirmations"], list) or len(r["confirmations"]) != 2 \
                or any(not isinstance(c, dict) or set(c) != {"by", "proof"} or not isinstance(c["by"], str)
                       or not 1 <= len(c["by"]) <= 256 or not isinstance(c["proof"], str) or not HEX64.fullmatch(c["proof"])
                       for c in r["confirmations"]) \
                or r["confirmations"][0]["by"] == r["confirmations"][1]["by"]:
            raise StoreRefused("restore is {mark, confirmations, trustees?}: a whole mark from 1 and two "
                               "confirmations {by, proof} by two different people, each proof 64 hex characters")
        _trustee_sigs(r)
    _ops(ch["ops"])
    _ha_change(body)
    return body


HA_MODES = ("set", "off", "break_glass")
_NODE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def _ha_change(body: dict) -> None:
    """The ha head record changes only by an HA change link, two people confirming it (decision 0031)."""
    ch = body["change"]
    touches = [op for op in ch["ops"] if op["kind"] == "head" and op["key"] == "ha"]
    if "ha" not in ch:
        if touches and body["seq"] != 0 and "migrate" not in ch:
            raise StoreRefused("the ha head record changes only by an HA change link, confirmed by the security officer "
                               "and a root trust owner (python -m keyclerk.ha)")
        return
    h = ch["ha"]
    if body["seq"] < 1 or "yaml" in ch or "migrate" in ch or "restore" in ch:
        raise StoreRefused("an HA change link follows the genesis and is no migrate or restore link")
    if not isinstance(h, dict) or h.get("mode") not in HA_MODES \
            or set(h) - {"trustees"} != ({"mode", "confirmations", "node"} if h["mode"] == "break_glass" else {"mode", "confirmations"}) \
            or ("node" in h and not (isinstance(h["node"], str) and _NODE.fullmatch(h["node"]))) \
            or not isinstance(h["confirmations"], list) or len(h["confirmations"]) != 2 \
            or any(not isinstance(c, dict) or set(c) != {"by", "proof"} or not isinstance(c["by"], str)
                   or not 1 <= len(c["by"]) <= 256 or not isinstance(c["proof"], str) or not HEX64.fullmatch(c["proof"])
                   for c in h["confirmations"]) \
            or h["confirmations"][0]["by"] == h["confirmations"][1]["by"]:
        raise StoreRefused("ha is {mode: set, off or break_glass, confirmations, node (break_glass only)}: two "
                           "confirmations {by, proof} by two different people, each proof 64 hex characters")
    want = "put" if h["mode"] == "set" else "del"
    if len(ch["ops"]) != 1 or len(touches) != 1 or touches[0]["op"] != want:
        raise StoreRefused(f"an HA change link of mode {h['mode']} carries one op: {want} head ha")


def _trustee_sigs(d: dict) -> None:
    sigs = d.get("trustees")
    if sigs is None:
        return
    if not isinstance(sigs, list) or not 2 <= len(sigs) <= 4 or any(
            not isinstance(x, dict) or set(x) != {"trustee_id", "sig"} or not isinstance(x["trustee_id"], str)
            or not 1 <= len(x["trustee_id"]) <= 64 or not isinstance(x["sig"], str) or not 1 <= len(x["sig"]) <= 16384
            for x in sigs):
        raise StoreRefused("trustees is two to four {trustee_id, sig}, signatures as text")


def ha_statement(realm: str, seq: int, prev: str, mode: str, node: str | None, value) -> bytes:
    """What two trustees sign for an HA change at one position (F1): the position, the mode, the node and the HA
    record's hash, so a signature for one change at one place is void at any other."""
    vs = hashlib.sha256(E.canonical(value)).hexdigest() if value is not None else None
    return E.canonical({"format": "kc-ha-change-v1", "realm": realm, "seq": seq, "prev": prev, "mode": mode,
                        "node": node, "value_sha256": vs})


def restore_statement(realm: str, seq: int, prev: str, mark: int) -> bytes:
    """What two trustees sign for a restore link at one position (F1, F8: the mark is theirs, not the key's)."""
    return E.canonical({"format": "kc-restore-v1", "realm": realm, "seq": seq, "prev": prev, "mark": mark})


def trustee_statement(body: dict) -> tuple[str, bytes] | None:
    """(label, statement bytes) the trustees must have signed for this link; None when it needs none."""
    ch = body["change"]
    if "ha" in ch:
        h = ch["ha"]
        value = next((op["record"]["value"] for op in ch["ops"] if op["op"] == "put"), None)
        return "kc-ha-change-v1", ha_statement(body["realm"], body["seq"], body["prev"], h["mode"], h.get("node"), value)
    if "restore" in ch:
        return "kc-restore-v1", restore_statement(body["realm"], body["seq"], body["prev"], ch["restore"]["mark"])
    return None


def check_trustees(body: dict) -> None:
    """Where this process pins a trustee set, an HA change link or a restore link from the pinned position on holds
    only with one officer's and one root trust owner's signatures over its statement (F1): the records key alone,
    and hashes of tokens a verifier cannot see, never decide them."""
    from keyclerk import trustees as T
    what = trustee_statement(body)
    if what is None:
        return
    try:
        trust = T.pinned()
    except (OSError, ValueError) as e:
        raise StoreRefused(f"the pinned trustee set cannot be read: {e}") from None
    if trust is None or body["seq"] < trust["since"]:
        return
    kind = "ha" if "ha" in body["change"] else "restore"
    sigs = body["change"][kind].get("trustees")
    if not sigs:
        raise StoreRefused(f"link {body['seq']}: an {'HA change' if kind == 'ha' else 'restore'} link without trustee "
                           "signatures; this verifier pins a trustee set, so the records key alone does not decide it")
    try:
        T.threshold(trust["set"], what[0], what[1], sigs)
    except T.TrusteeRefused as e:
        raise StoreRefused(f"link {body['seq']}: the trustee signatures do not hold: {e}") from None


def check_restore(body: dict, revision_before: int | None) -> None:
    """A restore link never lowers the revision: its mark is at least the revision the log has reached."""
    r = body["change"].get("restore")
    if r is not None and revision_before is not None and r["mark"] < revision_before:
        raise StoreRefused(f"a restore link's mark {r['mark']} is below revision {revision_before}, which the log reached")


def _message(label: str, raw: bytes) -> bytes:
    return label.encode("ascii") + b"\n" + raw


def _seal(key: Ed25519PrivateKey, label: str, body: dict) -> dict:
    raw = E.canonical(body)
    return {"bytes": base64.b64encode(raw).decode("ascii"), "signature": key.sign(_message(label, raw)).hex()}


def _key_for(pinned, label: str, raw: bytes) -> str:
    """The key that must have signed these bytes: the pinned key, or, for a records-key history (#41), the key in force
    at the link's seq or for the checkpoint's size. The position is read before the signature is checked only to
    choose the key; whatever it claims, the store's sequence check still places the link."""
    if isinstance(pinned, str):
        return pinned
    from keyclerk.records_keys import HistoryRefused
    try:
        body = E._parse(raw)
    except ValueError as e:
        raise StoreRefused(str(e)) from None
    pos = body.get("seq") if label == LINK_FORMAT else body.get("size")
    if not isinstance(pos, int) or isinstance(pos, bool) or pos < 0:
        raise StoreRefused(f"a {label} without a position")
    try:
        return pinned.key_at(pos) if label == LINK_FORMAT else pinned.checkpoint_key(pos)["key"]
    except HistoryRefused as e:
        raise StoreRefused(str(e)) from None


def key_at(pinned, seq: int) -> str:
    """The records key in force at link `seq`: the pinned key, or the history's window holding seq (#41)."""
    return pinned if isinstance(pinned, str) else pinned.key_at(seq)


def adopt_history(current, history, size: int, genesis: str):
    """The history a store with `size` links moves to (already verified by records_keys.advance against the trustees):
    it starts from the store's genesis key, it is newer than the one held, and it drops none of the store's links (a
    recovery that cuts links the store holds is truncated first, its links kept as evidence)."""
    if history.key_at(0) != genesis:
        raise StoreRefused("the history does not start from this store's records key")
    if not isinstance(history.chain, list):
        raise StoreRefused("a history without its sealed versions")
    if not isinstance(current, str) and history.version <= current.version:
        raise StoreRefused(f"history version {history.version} is not newer than {current.version}")
    b = history.switch
    if size > b and key_at(current, b) != history.key_at(b):
        raise StoreRefused(f"the history switches at link {b}, but this store holds {size} links signed under the older "
                           "key from there on: truncate to the switch first (they are kept as evidence)")
    return history


def switch_roots(pinned) -> dict[int, bytes]:
    """{size: root} of every checkpoint a records-key history's versions rest on (review N6): at each switch the log's
    root is what the trustees and the witness vouched for, so an older key's fork of the links before it is refused."""
    if isinstance(pinned, str):
        return {}
    got = getattr(pinned, "_switch_roots", None)
    if got is not None:
        return got
    from keyclerk.store import note as N
    docs = []
    for sealed in pinned.chain:
        try:
            docs.append(E._parse(base64.b64decode(sealed["bytes"])))
        except (ValueError, KeyError, TypeError):
            continue
    docs.append(pinned.doc)
    got = {}
    for d in docs:
        t = d.get("trusted") if isinstance(d, dict) else None
        if not t:
            continue
        try:
            _, size, root = N.parse_checkpoint(N.split(t["note"])[0])
        except (N.NoteRefused, KeyError, TypeError, ValueError):
            continue
        got[size] = root
    pinned._switch_roots = got
    return got


def check_switch_root(pinned, frontier: list, h: bytes) -> None:
    """Refuse the link with hash h when, appended to a log with this frontier, it reaches a switch whose vouched root
    is another (review N6)."""
    roots = switch_roots(pinned)
    if not roots:
        return
    from keyclerk.store import merkle
    nxt = merkle.push(list(frontier), h)
    size = merkle.size(nxt)
    want = roots.get(size)
    if want is not None and merkle.root(nxt) != want:
        raise StoreRefused(f"at link {size} the log's root is not the one the records-key history rests on: an older "
                           "key's fork of the links before a switch; not followed")


def held_history(chain: list, size: int, genesis: str):
    """What a store opening with these stored sealed versions checks with (review N1): the configured pin moved forward
    through them against the pinned trustees, or the genesis key alone. Nothing stored is trusted by itself."""
    from keyclerk import records_keys as RK
    from keyclerk import trustees as T
    try:
        pin, trust = RK.pinned(), T.pinned()
        h = RK.rebuild(pin, chain, trust["set"] if trust else None, genesis)
    except (OSError, ValueError) as e:
        raise StoreRefused(f"the store's records-key history does not hold against the pins: {e}") from None
    return genesis if h is None else h


def configured_history(current, size: int, genesis: str):
    """What a store opening with `current` checks with: the process's pinned history (records_keys.pinned) when it
    starts from this store's key and is newer than the one held; otherwise `current`."""
    from keyclerk import records_keys as RK
    try:
        pin = RK.pinned()
    except (OSError, ValueError) as e:
        raise StoreRefused(f"the pinned records-key history cannot be read: {e}") from None
    if pin is None or pin.key_at(0) != genesis or (not isinstance(current, str) and pin.version <= current.version):
        return current
    return adopt_history(current, pin, size, genesis)


def _open(sealed, pinned, label: str) -> tuple[bytes, dict]:
    """(message || signature, the parsed body): the signature checked first, over the bytes as they came. `pinned`
    is the records key in hex, or a records-key history (keyclerk.records_keys.KeyHistory)."""
    if not isinstance(sealed, dict) or set(sealed) != {"bytes", "signature"}:
        raise StoreRefused(f"a sealed {label} is exactly bytes and signature")
    try:
        raw = E._raw(sealed["bytes"])
    except ValueError as e:
        raise StoreRefused(str(e)) from None
    if len(raw) > MAX_LINK:
        raise StoreRefused(f"a {label} body is at most {MAX_LINK} bytes")
    msg = _message(label, raw)
    if not E._verifies(_key_for(pinned, label, raw), sealed["signature"], msg):
        raise StoreRefused(f"the {label} is not signed by the records key")
    try:
        body = E._parse(raw)
    except ValueError as e:
        raise StoreRefused(str(e)) from None
    return msg + bytes.fromhex(sealed["signature"]), body


# --- links ------------------------------------------------------------------------------------------------------------

def link_body(realm: str, seq: int, prev: str, fence: int, at: str, ops: list[dict], entry: dict,
              yaml: dict | None = None, migrate: dict | None = None, restore: dict | None = None,
              ha: dict | None = None) -> dict:
    """An unsigned link body, its structure checked: what a signer checks a change as before it signs anything."""
    change = {"ops": sorted(ops, key=lambda o: (o["kind"], o["key"])), "entry": entry, **({"yaml": yaml} if yaml else {}),
              **({"migrate": migrate} if migrate else {}), **({"restore": restore} if restore else {}),
              **({"ha": ha} if ha else {})}
    body = _body({"format": LINK_FORMAT, "realm": realm, "seq": seq, "prev": prev, "fence": fence, "at": at,
                  "change": change})
    E.canonical(body)                             # refuses floats and out-of-range integers now, not at signing
    return body


def seal_body(key: Ed25519PrivateKey, body: dict) -> dict:
    return _seal(key, LINK_FORMAT, _body(body))


def seal_link(key: Ed25519PrivateKey, realm: str, seq: int, prev: str, fence: int, at: str, ops: list[dict],
              entry: dict, yaml: dict | None = None, migrate: dict | None = None, restore: dict | None = None) -> dict:
    return seal_body(key, link_body(realm, seq, prev, fence, at, ops, entry, yaml, migrate, restore))


def open_link(sealed, pinned: str) -> tuple[dict, bytes]:
    """(the body, the link hash) of a link signed by the pinned key, or StoreRefused; no chain context."""
    data, body = _open(sealed, pinned, LINK_FORMAT)
    return _body(body), merkle.leaf(data)


def check_next(sealed, pinned: str, realm: str, size: int, head: bytes | None, fence: int) -> tuple[dict, bytes]:
    """A link that may follow a log of `size` links whose last hash is `head` and last fence `fence`."""
    body, h = open_link(sealed, pinned)
    follows(body, realm, size, head, fence)
    check_trustees(body)
    return body, h


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
