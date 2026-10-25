"""The records state from the links (decision 0022): every store, backup and standby is a replay of the log.

replay(links, pinned, realm, side) verifies every link as a store appends it (signed by the pinned key, in sequence,
each following the one before, fence never going down, the migration where it belongs) into the reference store, and
returns that store; side records (from a snapshot) go in first, so a migration is proven again at link k while the
signed YAML bytes are still kept.
records(view) gives a store's records in today's document shape, so the engine's checks read them unchanged:
each kind as a list ordered by key, the head fields at the top, the side table's visits and proof tokens joined back
in (a proof whose token was erased keeps the token's hash), and "revision" = base + seq - k: base the YAML revision
the genesis starts from (1 for a log that starts empty), k its migrate links. Genesis and migrate links all show the
YAML revision; the first change after them is the next one, so revision numbers continue across the move and the
migration never shows as k changes.
"""
from __future__ import annotations

import hashlib
from typing import Iterable

from keyclerk import edge as E
from keyclerk import records as R
from keyclerk.store import View
from keyclerk.store import link as L
from keyclerk.store.link import StoreRefused
from keyclerk.store.memory import MemoryStore

ERASED = "not re-provable: the YAML bytes were erased"
ERASED_MAP = "not re-provable: mapping rows were erased (decision 0028)"


def replay(links: Iterable[dict], pinned: str, realm: str,
           side: Iterable[tuple[str, str, dict]] = ()) -> MemoryStore:
    store = MemoryStore(pinned, realm)
    for kind, key, rec in side:
        store.side_put(kind, key, rec)
    for sealed in links:
        store.append(sealed)
    return store


def verify(view: View, pinned: str, realm: str) -> None:
    """A store's own log, checked without rebuilding its records (a signer at every start): every link signed by the
    pinned key and following the one before, the migration where it belongs, the root and head the store keeps equal
    to its links', and its newest checkpoint stating exactly the log at its size. StoreRefused says what failed. Records
    rebuilt from the replay and compared are the background full check's (decision 0022 S4)."""
    from keyclerk.store import merkle
    cp = view.checkpoint()
    cp_size = L.open_checkpoint(cp, pinned)["size"] if cp else None
    size, head, fence, k, frontier = 0, None, 1, 0, []
    for sealed in view.links():
        body, h = L.check_next(sealed, pinned, realm, size, head, fence)
        k = L.parts(body) if size == 0 else k
        L.check_migrate(body, k)
        size, head, fence, frontier = size + 1, h, body["fence"], merkle.push(frontier, h)
        if size == cp_size:
            L.check_checkpoint(cp, pinned, realm, size, merkle.root(frontier), head)
    if size != view.size() or head != view.head() or merkle.root(frontier) != view.root():
        raise StoreRefused("the store's size, head or root is not its links'")
    if cp is None and size:
        raise StoreRefused("the store holds links but no checkpoint")
    if cp_size is not None and cp_size > size:
        raise StoreRefused(f"the newest checkpoint covers {cp_size} links, the store holds {size}")


def side_of(view: View) -> list[tuple[str, str, dict]]:
    """Every side record of a store, to replay with its links."""
    return [(k, key, rec) for k in L.SIDE_KINDS for key, rec in view.side_scan(k)]


def genesis(view: View) -> dict:
    return E._parse(E._raw(view.link(0)["bytes"]))


def revision(view: View) -> int | None:
    if view.size() == 0:
        return None
    g = genesis(view)
    y = g["change"].get("yaml")
    base, k = (y["revision"], y["parts"]) if y else (1, 0)
    return base + max(0, view.size() - 1 - k)


def prove_migration(view: View, pinned: str) -> str:
    """At link k: the state equals the signed YAML revision the genesis names, by meaning, or StoreRefused. "proven",
    or ERASED when the YAML bytes are no longer kept (the chain is then all that is trusted)."""
    from keyclerk.store import migrate as M
    y = genesis(view)["change"]["yaml"]
    kept = view.side_get("genesis_yaml", y["sha256"])
    if kept is None:
        return ERASED
    raw = kept["text"].encode("utf-8")
    if not E._verifies(pinned, y["signature"], raw):
        raise StoreRefused("the YAML revision the genesis names is not signed by the records key")
    try:
        doc = M.loads_signed(kept["text"])
    finally:
        M.loads_signed.cache_clear()                      # needed once: no parsed YAML kept past the proof
    if doc.get("revision") != y["revision"]:
        raise StoreRefused(f"the genesis names YAML revision {y['revision']}, the kept bytes are revision {doc.get('revision')}")
    if y.get("rekeyed") is not None:              # decision 0028: the state is the revision re-keyed by the kept rows
        from keyclerk import anchors as A
        try:
            doc = M.rekeyed(doc, [r for _, r in view.side_scan("anchor_map")])
        except A.Unmapped:
            return ERASED_MAP
    want, got = M.meaning(doc), M.meaning(records(view))
    for kind in M.VISIT_KINDS:                            # visit files sit beside the YAML: only its own must be kept
        missing = set(want.pop(kind, [])) - set(got.pop(kind, []))
        if missing:
            raise StoreRefused(f"the migration lost {len(missing)} of the YAML revision's {kind}")
    if want != got:
        diff = sorted(k for k in set(want) | set(got) if want.get(k) != got.get(k))
        raise StoreRefused(f"after the migration the records differ from the signed YAML revision in: {', '.join(diff[:5])}")
    return "proven"


def records(view: View) -> dict:
    doc: dict = {}
    for key, rec in view.scan("head"):
        doc[key] = rec["value"]
    for kind in L.LOG_KINDS:
        if kind == "head":
            continue
        items = [rec for _, rec in view.scan(kind)]
        if kind in L.PROOF_KINDS:
            items = [_token(view, p) for p in items]
        if items or (kind in R.KINDS and kind not in R.OPTIONAL):
            doc[kind] = items
    for kind in ("visits", "visit_events", "badges"):
        items = [rec for _, rec in view.side_scan(kind)]
        if items:
            doc[kind] = items
    doc.setdefault("suspensions", [])
    if view.size():
        doc["revision"] = revision(view)
    return doc


def _token(view: View, p: dict) -> dict:
    t = view.side_get("proof_tokens", p["sha256"])
    return {"records": p["records"], "by": p["by"], "token": t["token"]} if t else p


def apply_ops(doc: dict, body: dict, view: View | None = None) -> dict:
    """The records after one link, from the records before it, in records()' shape and order (each kind by key):
    what a replay gives, without replaying from the genesis. Proof tokens are joined from view's side table."""
    new = {k: (list(v) if isinstance(v, list) else v) for k, v in doc.items()}
    for op in body["change"]["ops"]:
        kind, key = op["kind"], op["key"]
        if kind == "head":
            if op["op"] == "put":
                new[key] = op["record"]["value"]
            else:
                new.pop(key, None)
            continue
        items = [r for r in new.get(kind) or [] if _key(kind, r) != key]
        if op["op"] == "put":
            rec = op["record"]
            if kind in L.PROOF_KINDS and view is not None:
                rec = _token(view, rec)
            items.append(rec)
        items.sort(key=lambda r: _key(kind, r))
        if items or (kind in R.KINDS and kind not in R.OPTIONAL):
            new[kind] = items
        else:
            new.pop(kind, None)
    new.setdefault("suspensions", [])
    if "migrate" not in body["change"] and isinstance(new.get("revision"), int):
        new["revision"] += 1
    return new


def _key(kind: str, rec: dict) -> str:
    if kind in L.PROOF_KINDS:
        return rec.get("sha256") or hashlib.sha256(str(rec.get("token", "")).encode()).hexdigest()
    return L.record_key(kind, rec)
