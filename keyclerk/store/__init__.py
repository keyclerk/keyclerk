"""The records store under the signed change log (decision 0022): a narrow interface, two stores behind it.

The log is the source of truth. A store keeps the links, verifies each before it holds it (signed by the pinned records
key, next in sequence, following the head, fence not going down) and materializes the records the links leave; a
checkpoint is kept only when it states this log exactly. What a change may do (no rewritten history, no new check
error, proofs) is the checking signer's to decide, not the store's.

    open_store("memory:", pinned, realm)          the reference store: same interface, same tests (decision 0022 point 2)
    open_store("sqlite:PATH", pinned, realm)      the SQLite store (keyclerk.store.sqlite)

Read side (a store and its snapshots):
    size() head() root() checkpoint(size=None) link(seq) links(start, stop)
    get(kind, key)  range(kind, index, lo, hi=None)  scan(kind)  find(kind, field, values)  count(kind)
    side_get(kind, key)  side_scan(kind)
Write side (a store only):
    append(sealed link, side=()) -> link hash      side records are written with the link, or not at all
    append_checked(body, seal, side=(), check=None) -> (sealed, hash)
                                          an unsigned body applied, check(view) run on that state, and only then
                                          seal(body) called and the link kept, in one step; a refusal undoes it all
                                          and nothing is ever signed for a refused change
    add_checkpoint(sealed checkpoint)
    side_put(kind, key, record)  side_delete(kind, key)                    NOT IN THE LOG
    snapshot()  close()

The side table holds what must be erasable and so never enters the append-only log: visits, visit events, badges,
the broker's token behind each approval or proposal proof (keyed by the hash the log carries), and the signed YAML
revision a migrated log started from (keyed by the sha256 its genesis commits to). It is mutable, neither linked nor
signed, and part of every snapshot. Erasing the genesis YAML ends one thing only: the migration can no longer be
proven again by replay (migration() then says so); the chain and its checkpoints verify as before.

migration(): None for a log that started empty, else whether its migration was proven at link k against the signed
YAML ("proven") or could not be ("not re-provable: the YAML bytes were erased").

find(kind, field, values): the keys of the records whose field (refs_of) holds one of the values, ordered by key; the
working set loads records with it. get_many(kind, keys): the records of those keys there are, by key. count(kind):
how many records a kind holds.
range(kind, index, lo, hi): records whose index value is a string equal to lo (hi None) or in [lo, hi), ordered by
(value, key); scan(kind) orders by key. Ordering is always explicit, never the engine's.
"""
from __future__ import annotations

import hashlib
from typing import Iterator, Protocol

from keyclerk.store.link import LOG_KINDS, SIDE_KINDS, StoreRefused

__all__ = ["INDEXES", "Store", "StoreRefused", "View", "open_store"]

INDEXES = ("anchor", "group", "start", "end")      # each a record field; the SQLite store keeps a generated column
SIDE_IDS = {"visits": "visit_id", "visit_events": "event_id", "badges": "badge_id"}


class View(Protocol):
    def size(self) -> int: ...
    def head(self) -> bytes | None: ...
    def root(self) -> bytes: ...
    def checkpoint(self, size: int | None = None) -> dict | None: ...
    def link(self, seq: int) -> dict: ...
    def links(self, start: int = 0, stop: int | None = None) -> Iterator[dict]: ...
    def get(self, kind: str, key: str) -> dict | None: ...
    def range(self, kind: str, index: str, lo: str, hi: str | None = None) -> Iterator[tuple[str, dict]]: ...
    def scan(self, kind: str) -> Iterator[tuple[str, dict]]: ...
    def find(self, kind: str, field: str, values) -> list[str]: ...
    def get_many(self, kind: str, keys) -> dict[str, dict]: ...
    def count(self, kind: str) -> int: ...
    def side_get(self, kind: str, key: str) -> dict | None: ...
    def side_scan(self, kind: str) -> Iterator[tuple[str, dict]]: ...
    def migration(self) -> str | None: ...


class Store(View, Protocol):
    pinned: str
    realm: str
    def append(self, sealed: dict, side: list[tuple[str, str, dict]] = ()) -> bytes: ...
    def append_checked(self, body: dict, seal, side=(), check=None) -> tuple[dict, bytes]: ...
    def add_checkpoint(self, sealed: dict) -> None: ...
    def side_put(self, kind: str, key: str, record: dict) -> None: ...
    def side_delete(self, kind: str, key: str) -> None: ...
    def snapshot(self) -> View: ...
    def close(self) -> None: ...


REF_FIELDS = ("member.anchor", "member.group", "member.rule", "under", "by", "delegate", "group", "anchor", "owner",
              "director", "approved_by", "anchors", "start", "start_day", "grant_id", "lease", "identity_hash",
              "subject.anchor", "appointed_by", "parent", "id", "requested_by", "sponsor.anchor")


def refs_of(kind: str, rec: dict) -> list[tuple[str, str]]:
    """What a record is found by (decision 0022 S4, the working set): (field, value) for each REF_FIELDS value it has,
    one per item of a list; member.rule is "yes" for a rule membership; start_day is the date part of start."""
    out: set[tuple[str, str]] = set()
    for f in REF_FIELDS:
        if f == "start_day":
            v = rec.get("start")
            if isinstance(v, str) and len(v) >= 10:
                out.add((f, v[:10]))
            continue
        if f == "member.rule":
            if isinstance(rec.get("member"), dict) and "rule" in rec["member"]:
                out.add((f, "yes"))
            continue
        if "." in f:
            outer, inner = f.split(".", 1)
            v = rec.get(outer)
            v = v.get(inner) if isinstance(v, dict) else None
        else:
            v = rec.get(f)
        for x in (v if isinstance(v, list) else [v]):
            if isinstance(x, str):
                out.add((f, x))
    return sorted(out)


def check_ref(field: str) -> None:
    if field not in REF_FIELDS:
        raise StoreRefused(f"{str(field)[:40]}: not a field records are found by ({', '.join(REF_FIELDS)})")


def check_kind(kind: str) -> None:
    if kind not in LOG_KINDS:
        raise StoreRefused(f"{str(kind)[:40]}: not a kind of record in the log")


def check_range(index: str, lo, hi) -> None:
    if index not in INDEXES:
        raise StoreRefused(f"{str(index)[:40]}: not an index (one of {', '.join(INDEXES)})")
    if not isinstance(lo, str) or not (hi is None or isinstance(hi, str)):
        raise StoreRefused("a range is bounded by text")


def index_value(rec: dict, index: str) -> str | None:
    """A record's value in an index: the field when it is text, else nothing (as the generated column computes it)."""
    v = rec.get(index)
    return v if isinstance(v, str) else None


def in_range(v: str | None, lo: str, hi: str | None) -> bool:
    return v is not None and (v == lo if hi is None else lo <= v < hi)


def check_side(kind: str, key: str, record=None) -> None:
    """A side record: one of the erasable kinds, under its own key; a token under the hash the log carries for it."""
    if kind not in SIDE_KINDS:
        raise StoreRefused(f"{str(kind)[:40]}: not a kind kept outside the log ({', '.join(SIDE_KINDS)})")
    if not isinstance(key, str) or not 1 <= len(key) <= 256:
        raise StoreRefused(f"{kind}: a key is 1 to 256 characters")
    if record is None:
        return
    if not isinstance(record, dict):
        raise StoreRefused(f"{kind}: a record is an object")
    if kind == "proof_tokens":
        if set(record) != {"token"} or not isinstance(record["token"], str) \
                or hashlib.sha256(record["token"].encode()).hexdigest() != key:
            raise StoreRefused("a proof token is {\"token\": ...}, kept under its sha256")
    elif kind == "genesis_yaml":
        if set(record) != {"text"} or not isinstance(record["text"], str) \
                or hashlib.sha256(record["text"].encode("utf-8")).hexdigest() != key:
            raise StoreRefused("the genesis YAML is {\"text\": ...}, kept under the sha256 of its bytes")
    elif kind == "anchor_map":                    # decision 0028: an internal anchor's row, filed under that anchor
        from keyclerk import anchors
        if set(record) - {"anchor", "idp", "salt", "label", "sub"} or not anchors.is_internal(record.get("anchor"))                 or record.get("anchor") != key or not isinstance(record.get("idp"), str)                 or not isinstance(record.get("salt"), str) or len(record["salt"]) != 32:
            raise StoreRefused("an anchor_map row is {anchor, idp, salt, label?, sub?}, filed under its internal anchor")
    elif kind == "anchor_idp":                    # the reverse lookup: only the anchor, never the identity provider's id
        from keyclerk import anchors
        if set(record) != {"anchor"} or not anchors.is_internal(record["anchor"]) or len(key) != 64:
            raise StoreRefused("an anchor_idp row is {anchor}, filed under the sha256 of the identity provider's id")
    elif record.get(SIDE_IDS[kind]) != key:
        raise StoreRefused(f"{kind} {key[:40]}: the key is not the record's {SIDE_IDS[kind]}")


def open_store(url: str, pinned: str, realm: str) -> Store:
    if url == "memory:":
        from keyclerk.store.memory import MemoryStore
        return MemoryStore(pinned, realm)
    if url.startswith("sqlite:"):
        from keyclerk.store.sqlite import SqliteStore
        return SqliteStore(url[len("sqlite:"):], pinned, realm)
    raise StoreRefused("a store is memory: or sqlite:PATH")
