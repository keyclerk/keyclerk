"""Signed snapshots of the change log (decision 0022 point 1, issue 28): a store starts from one instead of applying
every link since the genesis.

A snapshot is two files: the state, every record of the log's kinds at a size, and a statement the records key signs
over the state's hash and the log's size, head, root and fence there. A store adopts it only when empty, and only
together with the links up to that size: each link is checked as an append checks it (the signature, the chain, the
fence, the migration's place), the root and head they reach must be the statement's, and the state must hash to the
statement's; only the ops are not applied. So a snapshot is checked against the log and spares the rebuild, never the
history (dropping old links behind a snapshot is decision 0028 point 2, not this).

    sealed     = {"bytes": base64(body bytes), "signature": hex}   as every signed object (link.py)
    message    = "kc-snapshot-v1" + "\\n" + body bytes
    body       = {"format", "realm", "size", "head", "root", "fence", "at", "parts" (k, the migrate links),
                  "migration" (the store's proof of the migration, or null), "restore" ([seq, mark] or null),
                  "state": {"sha256", "bytes", "records"}}
    state file = one canonical JSON object per line, {"kind", "key", "record"}, ordered by (kind, key) with the kinds in
                 code-point order; "head" lines are the head fields by name

The migration's proof is the signer's word in a snapshot (the signed YAML it compared may since have been erased): a
snapshot is taken only after the migration's last link. Side records (visits, proof tokens) are not in a snapshot;
they never were in the log.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
from typing import Callable, Iterable, Iterator

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from keyclerk.store import link as L
from keyclerk.store import merkle
from keyclerk.store.link import StoreRefused

FORMAT = "kc-snapshot-v1"
FIELDS = {"format", "realm", "size", "head", "root", "fence", "at", "parts", "migration", "restore", "state"}
MAX_LINE = 2 * L.MAX_LINK                        # one record; a link body is at most MAX_LINK


def _fence_parts(view, pinned: str) -> tuple[int, int]:
    first, _ = L.open_link(view.link(0), pinned)
    last, _ = L.open_link(view.link(view.size() - 1), pinned)
    return last["fence"], L.parts(first)


def state_lines(view) -> Iterator[bytes]:
    """The records of a view, one canonical line each, in the state file's order."""
    for kind in sorted(L.LOG_KINDS):
        for key, rec in view.scan(kind):
            yield E.canonical({"kind": kind, "key": key, "record": rec}) + b"\n"


def take(view, key: Ed25519PrivateKey, path: Path, at: str) -> dict:
    """The state of a read-only view written to path, and the statement over it sealed by the records key. The view
    must not change while it is read: a store's snapshot() or reader()."""
    size = view.size()
    if size < 1:
        raise StoreRefused("an empty log has no snapshot")
    fence, k = _fence_parts(view, view.pinned)
    if size <= k:
        raise StoreRefused(f"a snapshot comes after the migration's last link ({k}), not at {size} links")
    if not E.TIME.fullmatch(at):
        raise StoreRefused("at is a UTC time, YYYY-MM-DDTHH:MM:SSZ")
    sha, n, count = hashlib.sha256(), 0, 0
    tmp = Path(path).with_name(Path(path).name + ".tmp")
    with open(tmp, "wb") as f:
        for line in state_lines(view):
            f.write(line)
            sha.update(line)
            n, count = n + len(line), count + 1
    tmp.replace(path)
    restore = view.restore_point()
    body = {"format": FORMAT, "realm": view.realm, "size": size, "head": view.head().hex(), "root": view.root().hex(),
            "fence": fence, "at": at, "parts": k, "migration": view.migration() or None,
            "restore": list(restore) if restore else None,
            "state": {"sha256": sha.hexdigest(), "bytes": n, "records": count}}
    return L._seal(key, FORMAT, body)


def open_snapshot(sealed, pinned: str, realm: str) -> dict:
    """The statement, its signature by the records key checked first, then its shape and realm."""
    _, body = L._open(sealed, pinned, FORMAT)
    if set(body) != FIELDS or body["format"] != FORMAT:
        raise StoreRefused(f"not a {FORMAT} body")
    if body["realm"] != realm:
        raise StoreRefused(f"a snapshot of realm {str(body['realm'])[:40]}, not {realm}")
    for f, low in (("size", 1), ("fence", 1), ("parts", 0)):
        if not L._count(body[f], low):
            raise StoreRefused(f"{f} is a whole number from {low}")
    if body["size"] <= body["parts"]:
        raise StoreRefused("a snapshot comes after the migration's last link")
    if not all(isinstance(body[k], str) and L.HEX64.fullmatch(body[k]) for k in ("head", "root")):
        raise StoreRefused("head and root are 64 lower-case hex characters")
    if not isinstance(body["at"], str) or not E.TIME.fullmatch(body["at"]):
        raise StoreRefused("at is a UTC time, YYYY-MM-DDTHH:MM:SSZ")
    if body["migration"] is not None and not (isinstance(body["migration"], str) and body["migration"]):
        raise StoreRefused("migration is the store's proof or null")
    r = body["restore"]
    if r is not None and not (isinstance(r, list) and len(r) == 2 and all(L._count(x, 0) for x in r)):
        raise StoreRefused("restore is [seq, mark] or null")
    st = body["state"]
    if not (isinstance(st, dict) and set(st) == {"sha256", "bytes", "records"} and isinstance(st["sha256"], str)
            and L.HEX64.fullmatch(st["sha256"]) and L._count(st["bytes"], 0) and L._count(st["records"], 0)):
        raise StoreRefused("state is {sha256, bytes, records}")
    return body


def chain(links: Iterable[dict], body: dict, pinned: str, realm: str,
          keep: Callable[[int, dict, bytes, int], None]) -> list[tuple[int, bytes]]:
    """The links up to the snapshot's size, each checked as an append checks it and handed to keep(seq, sealed, hash,
    fence); the root, head, fence, migration and restore they reach must be the snapshot's. Returns the frontier."""
    size, head, fence, k, frontier, restore = 0, None, 1, 0, [], None
    for sealed in links:
        if size == body["size"]:
            raise StoreRefused(f"more links than the snapshot's {body['size']}: adopt with the links up to it only")
        lb, h = L.check_next(sealed, pinned, realm, size, head, fence)
        L.check_switch_root(pinned, frontier, h)          # review N6
        k = L.parts(lb) if size == 0 else k
        L.check_migrate(lb, k)
        if "restore" in lb["change"]:
            restore = [lb["seq"], lb["change"]["restore"]["mark"]]
        keep(size, sealed, h, lb["fence"])
        size, head, fence, frontier = size + 1, h, lb["fence"], merkle.push(frontier, h)
    if size != body["size"]:
        raise StoreRefused(f"the snapshot is at {body['size']} links, but {size} came with it")
    if head.hex() != body["head"] or merkle.root(frontier).hex() != body["root"]:
        raise StoreRefused(f"the snapshot's head or root is not the log's at {size} links: not this log's snapshot")
    if fence != body["fence"] or k != body["parts"] or restore != body["restore"]:
        raise StoreRefused("the snapshot's fence, migration parts or restore point is not the log's")
    return frontier


def records(path: Path, body: dict) -> Iterator[tuple[str, str, object]]:
    """The state file's records, each checked (a log kind, its key, strictly in order); the hash, length and count
    are checked after the last, so a caller applies them in a transaction it rolls back on StoreRefused."""
    sha, n, count, last = hashlib.sha256(), 0, 0, None
    with open(path, "rb") as f:
        for line in f:
            if len(line) > MAX_LINE or not line.endswith(b"\n"):
                raise StoreRefused("a state line is too long or not ended")
            sha.update(line)
            n, count = n + len(line), count + 1
            try:
                obj = E._parse(line[:-1])
            except ValueError as e:
                raise StoreRefused(f"state line {count}: {e}") from None
            if (set(obj) != {"kind", "key", "record"} or obj["kind"] not in L.LOG_KINDS
                    or not isinstance(obj["key"], str)):
                raise StoreRefused(f"state line {count}: not {{kind, key, record}} of a log kind")
            kind, key, rec = obj["kind"], obj["key"], obj["record"]
            if kind == "head":
                if key not in L.HEAD_FIELDS:
                    raise StoreRefused(f"state line {count}: {key[:40]} is not a head field")
            elif not L.KEY.fullmatch(key) or L.record_key(kind, rec) != key:
                raise StoreRefused(f"state line {count}: the key is not the record's")
            if last is not None and (kind, key) <= last:
                raise StoreRefused(f"state line {count}: out of order or repeated")
            last = (kind, key)
            yield kind, key, rec
    st = body["state"]
    if sha.hexdigest() != st["sha256"] or n != st["bytes"] or count != st["records"]:
        raise StoreRefused("the state file is not the one the snapshot was signed over")


def write_sealed(sealed: dict, path: Path) -> None:
    Path(path).write_text(json.dumps(sealed, sort_keys=True) + "\n", encoding="utf-8")


def read_sealed(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def replay_from(sealed: dict, state: Path, links: Iterable[dict], pinned: str, realm: str,
                side: Iterable[tuple[str, str, dict]] = ()):
    """The reference store from a snapshot and its log: the links up to the snapshot adopted (checked, not applied),
    the rest appended as any replay does. A full check rebuilds from it instead of from the genesis."""
    from keyclerk.store.memory import MemoryStore
    body = open_snapshot(sealed, pinned, realm)
    it = iter(links)
    upto = itertools.islice(it, body["size"])           # the rest stay in it, for the appends after
    store = MemoryStore(pinned, realm)
    for kind, key, rec in side:
        store.side_put(kind, key, rec)
    store.adopt(sealed, upto, state)
    for s in it:
        store.append(s)
    return store
