# SPDX-License-Identifier: EUPL-1.2
"""KeyClerk engine, step 2: per-person queues, leader leases and per-anchor
locks fenced by epoch, apply with approvals re-checked, takeover re-diff, and the signed reduction journal.

The store here is SQLite (stdlib) standing in for PostgreSQL: the same transactions (BEGIN IMMEDIATE), unique
constraints and row checks. The target is any object with add(group, anchor) and remove(group, anchor); calls are
idempotent. Time is always passed in, so tests drive it.

Rules (concurrency and high availability):
- one queue per (realm, anchor); reductions first, in a reserved lane; only widenings are debounced
- a reconciler acts only while it holds the realm's lease; the lease epoch is written with every per-anchor lock and
  both are re-checked in the same transaction immediately before each target call; locks live shorter than the
  lease; a reconciler that lost its lease stops
- locks over several anchors are taken in anchor-id order
- an approval is re-checked at apply time: record hash, base version and not_after
- after a takeover the new leader re-diffs every anchor the previous epoch touched
- every reduction is appended to a signed, hash-chained journal before it is applied; a reduction never waits for a
  widening
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta

LEASE = timedelta(seconds=15)
LOCK_TTL = timedelta(seconds=10)    # shorter than the lease
DEBOUNCE = timedelta(seconds=30)    # widenings only

REDUCTION, WIDENING = "reduction", "widening"
PRIORITY = {"revocation": 0, "narrowing": 1, "leaver": 2, "renewal": 3, "widening": 4}   # queue order: reductions first


class LostLease(Exception):
    """The reconciler no longer holds the lease: it must stop at once."""


def classify(op: dict) -> str:
    """Classify after the diff: a removal, or any change that ends or shortens access, is a reduction."""
    return REDUCTION if op["op"] == "remove" or op.get("kind") in ("revocation", "narrowing", "leaver") else WIDENING


def _ts(d: datetime) -> str:
    return d.isoformat()


class Store:
    """The engine's state in flight."""

    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS lease (realm TEXT PRIMARY KEY, holder TEXT, epoch INTEGER, expires TEXT);
            CREATE TABLE IF NOT EXISTS lock (anchor TEXT PRIMARY KEY, holder TEXT, epoch INTEGER, expires TEXT);
            CREATE TABLE IF NOT EXISTS touched (realm TEXT, epoch INTEGER, anchor TEXT, PRIMARY KEY (realm, epoch, anchor));
            CREATE TABLE IF NOT EXISTS inbox (event_id TEXT PRIMARY KEY, at TEXT);
            CREATE TABLE IF NOT EXISTS queue (id INTEGER PRIMARY KEY AUTOINCREMENT, realm TEXT, anchor TEXT, lane TEXT,
                priority INTEGER, due TEXT, op TEXT, done INTEGER DEFAULT 0);
        """)

    def tx(self):
        self.db.execute("BEGIN IMMEDIATE")
        return self.db

    # leases ------------------------------------------------------------------------------------------------------
    def acquire(self, realm: str, holder: str, now: datetime) -> int | None:
        db = self.tx()
        try:
            row = db.execute("SELECT holder, epoch, expires FROM lease WHERE realm=?", (realm,)).fetchone()
            if row and row[0] != holder and datetime.fromisoformat(row[2]) > now:
                db.execute("COMMIT")
                return None
            epoch = (row[1] if row else 0) + (0 if row and row[0] == holder else 1)
            db.execute("INSERT OR REPLACE INTO lease VALUES (?,?,?,?)", (realm, holder, epoch, _ts(now + LEASE)))
            db.execute("COMMIT")
            return epoch
        except Exception:
            db.execute("ROLLBACK")
            raise

    def current(self, realm: str) -> tuple[str, int, datetime] | None:
        row = self.db.execute("SELECT holder, epoch, expires FROM lease WHERE realm=?", (realm,)).fetchone()
        return (row[0], row[1], datetime.fromisoformat(row[2])) if row else None

    # inbox ---------------------------------------------------------------------------------------------------------
    def seen(self, event_id: str, now: datetime) -> bool:
        """Idempotent consumption by CloudEvents id."""
        try:
            self.db.execute("INSERT INTO inbox VALUES (?,?)", (event_id, _ts(now)))
            return False
        except sqlite3.IntegrityError:
            return True

    # queues --------------------------------------------------------------------------------------------------------
    def enqueue(self, realm: str, op: dict, now: datetime) -> None:
        lane = classify(op)
        due = now if lane == REDUCTION else now + DEBOUNCE
        prio = PRIORITY.get(op.get("kind", "widening" if lane == WIDENING else "revocation"), 4)
        if lane == WIDENING:   # debounce: a newer widening for the same group and anchor replaces the pending one
            self.db.execute("DELETE FROM queue WHERE realm=? AND anchor=? AND lane=? AND done=0 AND op=?",
                            (realm, op["anchor"], WIDENING, json.dumps(op, sort_keys=True)))
        self.db.execute("INSERT INTO queue (realm, anchor, lane, priority, due, op) VALUES (?,?,?,?,?,?)",
                        (realm, op["anchor"], lane, prio, _ts(due), json.dumps(op, sort_keys=True)))

    def due(self, realm: str, now: datetime, lane: str) -> list[tuple[int, dict]]:
        rows = self.db.execute(
            "SELECT id, op FROM queue WHERE realm=? AND lane=? AND done=0 AND due<=? ORDER BY priority, id",
            (realm, lane, _ts(now))).fetchall()
        return [(i, json.loads(o)) for i, o in rows]

    def mark(self, qid: int) -> None:
        self.db.execute("UPDATE queue SET done=1 WHERE id=?", (qid,))


class Journal:
    """The reduction journal: append-only, hash-chained and signed (HMAC here; an
    asymmetric key in production). Its head is anchored off the box with the revocation high-water set."""

    def __init__(self, key: bytes):
        self.key = key
        self.entries: list[dict] = []

    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else "0" * 64

    def append(self, entry: dict, now: datetime) -> dict:
        body = {"seq": len(self.entries) + 1, "at": _ts(now), "prev": self.head(), "entry": entry}
        raw = json.dumps(body, sort_keys=True).encode()
        rec = {**body, "hash": hashlib.sha256(raw).hexdigest(),
               "sig": hmac.new(self.key, raw, hashlib.sha256).hexdigest()}
        self.entries.append(rec)
        return rec

    def verify(self) -> list[str]:
        errs, prev = [], "0" * 64
        for i, rec in enumerate(self.entries, 1):
            body = {k: rec[k] for k in ("seq", "at", "prev", "entry")}
            raw = json.dumps(body, sort_keys=True).encode()
            if rec["seq"] != i or rec["prev"] != prev:
                errs.append(f"entry {i}: chain broken")
            if rec["hash"] != hashlib.sha256(raw).hexdigest() or not hmac.compare_digest(
                    rec["sig"], hmac.new(self.key, raw, hashlib.sha256).hexdigest()):
                errs.append(f"entry {i}: hash or signature wrong")
            prev = rec["hash"]
        return errs

    def revoked_ids(self) -> set[str]:
        return {r["entry"]["grant_id"] for r in self.entries if r["entry"].get("kind") == "revocation" and "grant_id" in r["entry"]}


def union_revocations(doc: dict, journal: Journal) -> dict:
    """The bundle builder and every restore take the union of the records and the journal."""
    have = {r["grant_id"] for r in doc.get("revocations", [])}
    extra = [{"grant_id": g, "at": "journal", "by": "journal", "reason": "reduction journal"} for g in sorted(journal.revoked_ids() - have)]
    return {**doc, "revocations": doc.get("revocations", []) + extra}


@dataclass
class Reconciler:
    """One reconciler process. It acts only while it holds the lease; every target call is fenced."""
    realm: str
    name: str
    store: Store
    target: object
    journal: Journal
    epoch: int | None = None
    applied: list = field(default_factory=list)

    def lead(self, now: datetime) -> bool:
        prev = self.store.current(self.realm)
        epoch = self.store.acquire(self.realm, self.name, now)
        if epoch is None:
            self.epoch = None
            return False
        if prev and prev[0] != self.name:
            self._takeover(prev[1], now)
        self.epoch = epoch
        return True

    def _takeover(self, old_epoch: int, now: datetime) -> None:
        """Re-diff every anchor the previous epoch touched: queue a fresh check for each."""
        for (anchor,) in self.store.db.execute("SELECT anchor FROM touched WHERE realm=? AND epoch=?", (self.realm, old_epoch)):
            self.store.enqueue(self.realm, {"op": "rediff", "anchor": anchor, "kind": "narrowing"}, now)

    def _fenced(self, anchors: list[str], now: datetime, call) -> None:
        """Take the anchors' locks in id order, re-check lease and locks in the same transaction, then call."""
        db = self.store.tx()
        try:
            lease = db.execute("SELECT holder, epoch, expires FROM lease WHERE realm=?", (self.realm,)).fetchone()
            if not lease or lease[0] != self.name or lease[1] != self.epoch or datetime.fromisoformat(lease[2]) <= now:
                db.execute("ROLLBACK")
                self.epoch = None
                raise LostLease(self.name)
            for a in sorted(anchors):   # one global order, so acts on two anchors never deadlock
                row = db.execute("SELECT holder, epoch, expires FROM lock WHERE anchor=?", (a,)).fetchone()
                if row and row[0] != self.name and datetime.fromisoformat(row[2]) > now:
                    db.execute("ROLLBACK")
                    raise LostLease(f"{a} locked by {row[0]}")
                db.execute("INSERT OR REPLACE INTO lock VALUES (?,?,?,?)", (a, self.name, self.epoch, _ts(now + LOCK_TTL)))
                db.execute("INSERT OR IGNORE INTO touched VALUES (?,?,?)", (self.realm, self.epoch, a))
            call()   # the target call happens inside the fenced transaction window
            db.execute("COMMIT")
        except LostLease:
            raise
        except Exception:
            db.execute("ROLLBACK")
            raise

    def apply(self, op: dict, now: datetime, approvals_ok=lambda op, now: True) -> str:
        if self.epoch is None:
            raise LostLease(self.name)
        if classify(op) == WIDENING and not approvals_ok(op, now):
            return "refused: approval no longer holds"
        if classify(op) == REDUCTION:
            self.journal.append({k: op[k] for k in op if k in ("op", "group", "anchor", "kind", "grant_id")}, now)
        if op["op"] == "rediff":
            return "rediff"
        fn = (lambda: self.target.remove(op["group"], op["anchor"], self.epoch)) if op["op"] == "remove" else \
             (lambda: self.target.add(op["group"], op["anchor"], self.epoch))
        self._fenced([op["anchor"]], now, fn)
        self.applied.append((self.epoch, op["op"], op["group"], op["anchor"]))
        return "applied"

    def run(self, now: datetime, approvals_ok=lambda op, now: True) -> list[str]:
        """Drain due work: the reduction lane first, then widenings; a lost lease stops the run at once."""
        out = []
        for lane in (REDUCTION, WIDENING):
            for qid, op in self.store.due(self.realm, now, lane):
                out.append(self.apply(op, now, approvals_ok))
                self.store.mark(qid)
        return out


def approval_holds(op: dict, now: datetime, records_hash: str, base_version: int) -> bool:
    """An approval binds the record hash, the base version and not_after; any mismatch refuses it."""
    a = op.get("approval", {})
    return (a.get("record_hash") == records_hash and a.get("base_version") == base_version
            and datetime.fromisoformat(a["not_after"]) > now)
