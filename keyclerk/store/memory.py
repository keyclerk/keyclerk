"""The in-memory reference store (decision 0022 point 2): the same interface and the same tests as the SQLite store, so the
interface cannot drift towards what one engine happens to do. Records are kept as their canonical bytes and parsed on
every read, as the SQLite store does, so no caller can change what the next one reads."""
from __future__ import annotations

import copy
import json
import threading
from typing import Iterator

from keyclerk import edge as E
from keyclerk.store import check_kind, check_range, check_ref, check_side, in_range, index_value, refs_of
from keyclerk.store import link as L
from keyclerk.store import merkle
from keyclerk.store.link import StoreRefused


class MemoryStore:
    def __init__(self, pinned: str, realm: str):
        E.load_public(pinned)
        self.pinned, self.realm = pinned, realm
        self._links: list[dict] = []
        self._hashes: list[bytes] = []
        self._fence = 1
        self._frontier: list[tuple[int, bytes]] = []
        self._records: dict[tuple[str, str], bytes] = {}
        self._side: dict[tuple[str, str], bytes] = {}
        self._checkpoints: dict[int, dict] = {}
        self._parts = 0                                 # k, the migrate links after the genesis
        self._migration: str | None = None
        self._frozen = False
        self._lock = threading.Lock()

    # --- write ------------------------------------------------------------------------------------------------------

    def _writable(self) -> None:
        if self._frozen:
            raise StoreRefused("a snapshot is read only")

    def append(self, sealed: dict, side: list[tuple[str, str, dict]] = ()) -> bytes:
        with self._lock:
            self._writable()
            for kind, key, rec in side:
                check_side(kind, key, rec)
            body, h = L.check_next(sealed, self.pinned, self.realm, len(self._links), self.head(), self._fence)
            return self._apply(body, side, None, lambda: (sealed, h))[1]

    def append_checked(self, body: dict, seal, side: list[tuple[str, str, dict]] = (), check=None) -> tuple[dict, bytes]:
        """An unsigned body applied and checked; seal(body) is called only when the checks pass, and the sealed link is
        kept in the same step. A refusal undoes it all, and nothing was ever signed."""
        with self._lock:
            self._writable()
            for kind, key, rec in side:
                check_side(kind, key, rec)
            size, head, fence = len(self._links), self.head(), self._fence
            L.follows(L._body(body), self.realm, size, head, fence)

            def finish():
                sealed = seal(body)
                signed, h = L.check_next(sealed, self.pinned, self.realm, size, head, fence)
                if signed != body:
                    raise StoreRefused("the sealed link is not the body that was checked")
                return sealed, h
            return self._apply(body, side, check, finish)

    def _apply(self, body: dict, side, check, finish) -> tuple[dict, bytes]:
        k = self._parts if self._links else L.parts(body)
        L.check_migrate(body, k)
        staged = {}
        for op in body["change"]["ops"]:
            at = (op["kind"], op["key"])
            if op["op"] == "put":
                staged[at] = E.canonical(op["record"])
            elif at not in self._records:
                raise StoreRefused(f"{op['kind']} {op['key']}: deleted, but there is no such record")
            else:
                staged[at] = None
        last = bool(k) and body["seq"] == k             # the last migrate link: proven before it is kept
        undo = (dict(self._records), dict(self._side), self._parts, self._migration)
        for key, v in staged.items():                   # every op checked first: a link applies whole or not at all
            if v is None:
                del self._records[key]
            else:
                self._records[key] = v
        for kind, key, rec in side:                     # with the link, or not at all
            self._side[(kind, key)] = E.canonical(rec)
        self._parts = k
        try:
            if last:                                    # the signed YAML, by meaning
                from keyclerk.store.replay import prove_migration
                self._migration = prove_migration(self, self.pinned)
            if check is not None:
                check(self)                             # the state with the change applied, before the link is kept
            sealed, h = finish()
        except BaseException:
            self._records, self._side, self._parts, self._migration = undo
            raise
        self._links.append({"bytes": sealed["bytes"], "signature": sealed["signature"]})
        self._hashes.append(h)
        self._fence = body["fence"]
        self._frontier = merkle.push(self._frontier, h)
        return sealed, h

    def add_checkpoint(self, sealed: dict) -> None:
        with self._lock:
            self._writable()
            L.check_checkpoint(sealed, self.pinned, self.realm, len(self._links), self.root(), self.head())
            cp = {"bytes": sealed["bytes"], "signature": sealed["signature"]}
            if self._checkpoints.get(len(self._links), cp) != cp:
                raise StoreRefused(f"another checkpoint is already kept at {len(self._links)} links")
            self._checkpoints[len(self._links)] = cp

    def side_put(self, kind: str, key: str, record: dict) -> None:
        with self._lock:
            self._writable()
            check_side(kind, key, record)
            self._side[(kind, key)] = E.canonical(record)

    def side_delete(self, kind: str, key: str) -> None:
        with self._lock:
            self._writable()
            check_side(kind, key)
            self._side.pop((kind, key), None)

    def reader(self) -> "MemoryStore":
        """A read-only view of the state as it stands now (a copy: later writes do not reach it)."""
        return self.snapshot()

    def snapshot(self) -> "MemoryStore":
        with self._lock:
            snap = copy.copy(self)
            snap._links, snap._hashes, snap._frontier = list(self._links), list(self._hashes), list(self._frontier)
            snap._records, snap._side, snap._checkpoints = dict(self._records), dict(self._side), dict(self._checkpoints)
            snap._frozen, snap._lock = True, threading.Lock()
            return snap

    def close(self) -> None:
        pass

    # --- read -------------------------------------------------------------------------------------------------------

    def size(self) -> int:
        return len(self._links)

    def migration(self) -> str | None:
        return self._migration

    def head(self) -> bytes | None:
        return self._hashes[-1] if self._hashes else None

    def root(self) -> bytes:
        return merkle.root(self._frontier)

    def checkpoint(self, size: int | None = None) -> dict | None:
        if size is not None:
            cp = self._checkpoints.get(size)
            return dict(cp) if cp else None
        return dict(self._checkpoints[max(self._checkpoints)]) if self._checkpoints else None

    def link(self, seq: int) -> dict:
        if not 0 <= seq < len(self._links):
            raise StoreRefused(f"there is no link {seq}")
        return dict(self._links[seq])

    def links(self, start: int = 0, stop: int | None = None) -> Iterator[dict]:
        for s in self._links[start:stop]:
            yield dict(s)

    def get(self, kind: str, key: str) -> dict | None:
        check_kind(kind)
        b = self._records.get((kind, key))
        return json.loads(b) if b is not None else None

    def range(self, kind: str, index: str, lo: str, hi: str | None = None) -> Iterator[tuple[str, dict]]:
        check_kind(kind)
        check_range(index, lo, hi)
        hits = []
        for (k, key), b in self._records.items():
            if k == kind:
                rec = json.loads(b)
                v = index_value(rec, index)
                if in_range(v, lo, hi):
                    hits.append((v, key, rec))
        for _, key, rec in sorted(hits, key=lambda t: (t[0], t[1])):
            yield key, rec

    def find(self, kind: str, field: str, values) -> list[str]:
        """By scanning: the reference the SQLite store's refs index is held to."""
        check_kind(kind)
        check_ref(field)
        want = {(field, v) for v in values}
        return sorted(key for (k, key), b in self._records.items() if k == kind and want & set(refs_of(kind, json.loads(b))))

    def get_many(self, kind: str, keys) -> dict[str, dict]:
        check_kind(kind)
        return {k: json.loads(self._records[(kind, k)]) for k in keys if (kind, k) in self._records}

    def count(self, kind: str) -> int:
        check_kind(kind)
        return sum(1 for k, _ in self._records if k == kind)

    def scan(self, kind: str) -> Iterator[tuple[str, dict]]:
        check_kind(kind)
        for key in sorted(key for (k, key) in self._records if k == kind):
            yield key, json.loads(self._records[(kind, key)])

    def side_get(self, kind: str, key: str) -> dict | None:
        check_side(kind, key)
        b = self._side.get((kind, key))
        return json.loads(b) if b is not None else None

    def side_scan(self, kind: str) -> Iterator[tuple[str, dict]]:
        check_side(kind, "-")
        for key in sorted(key for (k, key) in self._side if k == kind):
            yield key, json.loads(self._side[(kind, key)])
