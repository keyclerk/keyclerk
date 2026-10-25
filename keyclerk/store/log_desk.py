# SPDX-License-Identifier: EUPL-1.2
"""The desk on the signed change log (decision 0022, S5 step T3): store.kind sqlite.

The desk never signs a change. It turns the document its logic produced into ops against the records it holds,
proposes them through the checking signer, and appends the link the signer answers with to its own replica
(store/follow.py). What only the desk holds, visits with their events and badges, lives in its replica's side tables;
its activity lines (refused, pending, edge events) stay in log.jsonl, each signed by the signer, as on the YAML store.

    LogStore(path, signer, seed=None)    path: the desk's directory; signer: the checking signer (or its client)

At start the store catches up with the signer. A signer with no change log yet is started empty and seeded from
--seed, its first change judged whole; a signer that holds a signed YAML revision is migrated instead (op migrate,
python -m keyclerk.store.migrate). The replica file is named in log.current, so a resync swaps in a new file and a
restart opens the one the last resync left.
"""
from __future__ import annotations

import copy
import hashlib
import json
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path

from keyclerk import guard, records
from keyclerk import anchors as A
from keyclerk.desk import DeskFiles, Refusal, StoreFault, _atomic, _without_visitors
from keyclerk.store import link as L
from keyclerk.store import migrate as M
from keyclerk.store import replay as RP
from keyclerk.store.follow import Follower
from keyclerk.store.sqlite import SqliteStore

VISIT_KINDS = (("visits", "visit_id"), ("visit_events", "event_id"), ("badges", "badge_id"))
# What of the desk's entry a link keeps for good (decision 0028 point 7): its structure, never free text. The summary
# and the reasons, which can name people, stay in the desk's activity log, whose line points at the link.
LINK_ENTRY = ("change_id", "action", "actor", "outcome", "records")
CURRENT = "log.current"


def _digest(x) -> str:
    return hashlib.sha256(json.dumps(x, sort_keys=True, default=str).encode()).hexdigest()


def ops_between(old: dict, new: dict) -> tuple[list[dict], list[list[str]]]:
    """(ops, proof tokens) that turn the records old into new: a put for every record new or changed, a del for every
    record gone, and the token of every proof new puts. Visits are not records of the log and are left out."""
    def keyed(doc):
        head, ops, side = M.split({k: v for k, v in doc.items() if k not in dict(VISIT_KINDS)})
        return {(o["kind"], o["key"]): o for o in head + ops}, dict(side.get("proof_tokens") or [])
    was, _ = keyed(old)
    now, tokens = keyed(new)
    puts = [o for k, o in now.items() if was.get(k) != o]
    dels = [{"op": "del", "kind": k, "key": key} for (k, key) in was if (k, key) not in now]
    fresh = {o["key"] for o in puts if o["kind"] in L.PROOF_KINDS}
    return sorted(puts + dels, key=lambda o: (o["kind"], o["key"])), \
        [[sha, t["token"]] for sha, t in sorted(tokens.items()) if sha in fresh]


class LogStore(DeskFiles):
    scoped_judging = True                     # the desk judges a change on what it reaches (S5 T9); the signer re-judges

    def __init__(self, path: Path, signer, seed: Path | None = None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if signer is None:
            raise StoreFault("the desk on the change log needs the checking signer (--signer): only it signs")
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        self._signer, self._key, self._commit_sig = signer, None, None
        self._pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer.public_key()))
        self._wlock = threading.RLock()
        self._hold()
        try:
            self._open_log(seed)
        except BaseException:      # a refusal releases what it took: the replica file and the directory lock
            if getattr(self, "follower", None) is not None:
                self.follower.store.close()
            DeskFiles.close(self)
            raise

    def _open_log(self, seed: Path | None) -> None:
        signer = self._signer
        self._head: tuple[int, str] | None = None            # (last seq, last sha256) of the activity log
        self._verified = (0, "0" * 64, [], 0, 0.0)
        self.recovered: list[str] = []
        self._gen = 0                                          # counts the desk's own side writes (visits)
        self.follow_failure: str | None = None                # why the last refresh could not follow the signer
        self._merged: tuple[str, dict] | None = None
        head = signer.head()
        if head.get("broken"):
            raise StoreFault(f"the checking signer will not serve its change log: {head['broken']}")
        self.frozen = head.get("frozen")
        seed_doc = records.loads(guard.read_bounded(Path(seed))) if seed else None
        if head.get("migrated") is False:
            if seed_doc is None:
                raise StoreFault("the checking signer keeps no change log yet: migrate its signed YAML revision "
                                 "(python -m keyclerk.store.migrate), or start an empty desk with --seed records")
            signer.start(seed_doc["realm"])
            head = signer.head()
        realm = seed_doc["realm"] if not head.get("checkpoint") else \
            L.open_checkpoint(head["checkpoint"], signer.public_key())["realm"]
        if seed_doc is not None and seed_doc.get("realm") != realm:
            raise StoreFault(f"the seed is for realm {seed_doc.get('realm')!r}, the signer's log for {realm!r}")
        self.realm = realm
        self.follower = Follower(self._open(self._current()), signer, self._fresh)
        self._not_ahead(head)
        self.follower.catch_up()
        self._sync_anchors()
        self._note_unnoted()
        if self.store.size() == 0:
            if seed_doc is None:
                raise StoreFault("the signer's change log is empty: start the desk with --seed records")
            self._seed(seed_doc)

    # --- the replica ------------------------------------------------------------------------------------------------

    @property
    def store(self):
        return self.follower.store

    def _current(self) -> str:
        f = self.path / CURRENT
        name = f.read_text(encoding="utf-8").strip() if f.exists() else "log.db"
        if not name.startswith("log") or not name.endswith(".db") or "/" in name or "\\" in name:
            raise StoreFault(f"{CURRENT} names {name[:40]!r}, not a replica file of this directory")
        return name

    def _open(self, name: str) -> SqliteStore:
        try:
            return SqliteStore(self.path / name, self._signer.public_key(), self.realm)
        except L.StoreRefused as e:
            raise StoreFault(f"the desk's replica {name} does not open: {e}") from None

    def _fresh(self) -> SqliteStore:
        """An empty replica file for a resync; log.current names it once the resync is through (see _resynced)."""
        name = f"log-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(3)}.db"
        self._pending_name = name
        return self._open(name)

    def resync(self) -> None:
        with self._wlock:
            old = self._current()
            self.follower.resync()
            self._sync_anchors()
            _atomic(self.path / CURRENT, self._pending_name.encode())
            for suffix in ("", "-wal", "-shm"):
                (self.path / (old + suffix)).unlink(missing_ok=True)
            self._merged, self._log_doc = None, None

    def _sync_anchors(self) -> None:
        """The signer's mapping rows, mirrored (decision 0028): new and linked rows taken, erased ones dropped."""
        from keyclerk.store.log_reconcile import sync_rows
        sync_rows(self.store, self._signer)

    def _put_row(self, row: dict) -> None:
        self.store.side_put("anchor_map", row["anchor"], row)
        self.store.side_put("anchor_idp", A.idp_key(row["idp"]), {"anchor": row["anchor"]})

    def refresh(self) -> None:
        """What the signer learned since: links proposed elsewhere, subjects the reconciler linked, and whether signing
        is frozen. A failure is kept with its reason (readiness, keyclerk_log_breaks) and raised; the next refresh tries
        again, and the desk reads on from its replica meanwhile."""
        with self._wlock:
            try:
                head = self._signer.head()
                if head.get("broken"):
                    raise StoreFault(f"the checking signer will not serve its change log: {head['broken']}")
                self.frozen = head.get("frozen")
                self._not_ahead(head)
                self.follower.catch_up()
                self._sync_anchors()
            except Exception as e:
                self.follow_failure = f"{type(e).__name__}: {str(e)[:200]}"
                raise
            self.follow_failure = None
            self._merged = None

    def follow_breaks(self) -> int:
        """Times this desk could not follow the signer: resyncs after a link it refused, and a failed refresh."""
        return len(self.follower.alarms) + (1 if self.follow_failure else 0)

    def _not_ahead(self, head: dict) -> None:
        """A replica never ahead of the signer, nor on another history (decision 0019's restore guard, the desk's
        side): it is restored from a newer backup than the signer's state, or it follows another signer."""
        size = head.get("size")
        if not isinstance(size, int) or self.store.size() == 0:
            return
        if self.store.size() > size:
            raise StoreFault(f"the desk's replica holds {self.store.size()} links, the signer {size}: a desk restored from "
                             "a newer backup than its signer. Restore the signer's state from the same backup, or delete "
                             f"the desk's replica ({self._current()}) so it is rebuilt from the signer")
        at = self.store.size() - 1
        if at == size - 1 and self.store.head().hex() != head.get("head"):
            raise StoreFault("the desk's replica and the signer's log differ at the same length: another signer, or "
                             f"another history. Delete the desk's replica ({self._current()}) to rebuild it from this signer")

    def _note_unnoted(self) -> None:
        """A desk that stopped between a signed link and its activity line (a crash): one line per link the activity
        log does not name yet, marked recovered, so the history misses no change."""
        lines = self.log(500)
        if not lines:
            return
        noted = max((x["link"] for x in lines if isinstance(x.get("link"), int)), default=None)
        if noted is None:
            return
        for seq in range(noted + 1, self.store.size()):
            body, _ = L.open_link(self.store.link(seq), self._signer.public_key())
            e = body["change"]["entry"]
            self.note({k: e[k] for k in ("change_id", "action", "actor") if k in e}
                      | {"outcome": "applied", "link": seq, "recovered": True,
                         "reasons": ["the desk stopped before it wrote this line: written at its next start"]})

    def inward(self, value: str) -> str | None:
        """The internal anchor for a value naming a person, or None when the store knows no such person (0028)."""
        return A.inward(self.store, value)

    def _internal(self, doc: dict) -> tuple[dict, list[dict]]:
        """doc as the log carries it (decision 0028): every account re-keyed through the mapping, and for an account the
        store does not map yet a new internal anchor, its mapping row, and its accounts record in the same change."""
        found = M._anchors_of(doc)
        if not found:
            return doc, []
        labels = {a: p.get("person") for p in doc.get("persons") or [] for a in A.accounts(p)}
        rows, new = [], []
        for a in found:
            hit = self.store.side_get("anchor_idp", A.idp_key(a))
            if hit is not None:
                rows.append(self.store.side_get("anchor_map", hit["anchor"]))
            else:
                row = A.mapping_row(a, label=labels.get(a))
                rows.append(row)
                new.append(row)
        return M.rekeyed(doc, rows), new

    def _internal_ops(self, ops: list[dict]) -> tuple[list[dict], list[dict]]:
        """Ops as the log carries them (decision 0028): each record re-keyed through the mapping, and for an account the
        store does not map yet a new anchor, its mapping row, and its accounts record in the same change."""
        from keyclerk import records as R
        ops = M._json(ops)                            # as a link holds them: times as text
        names: set[str] = set()
        for op in ops:
            if op["op"] != "put":
                continue
            kind, recs = (op["key"], op["record"].get("value")) if op["kind"] == "head" else (op["kind"], op["record"])
            for rec in recs if isinstance(recs, list) else [recs]:
                if isinstance(rec, dict):
                    names |= {v for _, v in R.anchor_values(kind, rec) if A.is_person(v) and not A.is_internal(v)}
        amap, rows = {}, []
        for n in sorted(names):
            hit = self.store.side_get("anchor_idp", A.idp_key(n))
            if hit is not None:
                amap[n] = hit["anchor"]
            else:
                row = A.mapping_row(n)
                amap[n] = row["anchor"]
                rows.append(row)
        out = []
        for op in ops:
            if op["op"] == "put" and op["kind"] == "head":
                out.append({**op, "record": {"value": A.rekey({op["key"]: op["record"]["value"]}, amap)[op["key"]]}})
            elif op["op"] == "put":
                out.append({**op, "record": A.rekey({op["kind"]: [op["record"]]}, amap)[op["kind"]][0]})
            else:
                out.append(op)
        out += [{"op": "put", "kind": "accounts", "key": r["anchor"],
                 "record": {"anchor": r["anchor"], "commit": A.commitment(r["salt"], r["idp"])}} for r in rows]
        return sorted(out, key=lambda o: (o["kind"], o["key"])), rows

    def _seed(self, doc: dict) -> None:
        doc, rows = self._internal(doc)
        ops, tokens = ops_between({}, doc)
        self._propose(ops, tokens, rows, {"change_id": "C-" + secrets.token_hex(6), "action": "seed", "actor": None,
                                          "outcome": "applied"})
        self._write_visits(doc)
        self.note({"action": "seed", "actor": None, "outcome": "applied", "link": self.store.size() - 1})

    def _propose(self, ops: list[dict], tokens: list, rows: list[dict], entry: dict) -> dict:
        from keyclerk.signer import SignerRefused
        change = {"ops": ops, "entry": entry}
        try:
            answer = self._signer.propose(self.follower.base(), change, tokens, rows or None)
        except SignerRefused as e:
            if str(e).startswith("stale"):           # another writer, or a link this desk has not followed yet
                try:
                    self.refresh()
                except Exception:   # noqa: BLE001 - the refusal below stands either way
                    pass
                raise Refusal("the records changed while this change was prepared: nothing was signed; look again "
                              "and propose it again") from None
            raise
        except OSError as e:                          # no write buffer (the fault model): the desk reads on
            raise Refusal(f"the checking signer does not answer ({type(e).__name__}): nothing was signed. The desk reads "
                          "on from its replica; propose again when the signer answers") from None
        if "duplicate" in answer:                              # applied before; its answer was lost
            self.follower.catch_up()
        else:
            self.follower.apply(answer, tokens)
        for row in rows:
            if self.store.side_get("anchor_map", row["anchor"]) is None:
                self._put_row(row)
        self._merged = None
        return answer

    def judge(self, ops: list[dict]) -> set[str] | None:
        """The engine errors these ops add, judged on what they reach, on this replica with the ops tried and rolled
        back (decision 0022 S5 T9): exactly the signer's judgement. None when the change reaches everyone or its
        working set is too wide: the desk then judges in full, as before."""
        from keyclerk import metrics, scope
        from keyclerk.store.working import fresh_errors, scoped_judgement
        with self._wlock:
            revision = self.revision()
            old_view = self.store.reader()
            try:
                got = self.store.trial(ops, lambda view: scoped_judgement(old_view, view, ops, revision))
            finally:
                old_view.close()
        if isinstance(got, scope.Full):
            metrics.inc("keyclerk_check_fallback_total", reason=got.reason)
            return None
        old, new, reach = got
        return fresh_errors(old, new, reach, ops)

    # --- what the desk reads ----------------------------------------------------------------------------------------

    def revision(self) -> int:
        return RP.revision(self.store) or 0

    def state_key(self) -> str:
        h = self.store.head()
        return f"{h.hex() if h else '-'}:{self._gen}"

    def load(self) -> dict:
        key = self.state_key()
        if self._merged is None or self._merged[0] != key:
            self._merged = (key, self._records_now())
        return copy.deepcopy(self._merged[1])

    def _records_now(self) -> dict:
        """The records with the visits joined: the log's part moved forward by the newest link when the last one read
        is the link before it (replay.apply_ops, the replay's own step), replayed whole otherwise."""
        size = self.store.size()
        last = getattr(self, "_log_doc", None)
        if last is not None and last[0] == size:
            doc = last[1]
        elif last is not None and last[0] == size - 1:
            body, _ = L.open_link(self.store.link(size - 1), self._signer.public_key())
            doc = RP.apply_ops(last[1], body, self.store)
        else:
            doc = {k: v for k, v in RP.records(self.store).items() if k not in dict(VISIT_KINDS)}
        self._log_doc = (size, doc)
        visits = {kind: [rec for _, rec in self.store.side_scan(kind)] for kind, _ in VISIT_KINDS}
        return {**doc, **{k: v for k, v in visits.items() if v}}

    # --- what the desk writes ---------------------------------------------------------------------------------------

    def commit(self, doc: dict, entry: dict, ops: list[dict] | None = None, tokens: list | None = None) -> dict:
        """A whole new document: its record changes proposed through the signer as one change, then its visits. ops:
        the change as the desk judged it (S5 T9), re-keyed record by record, instead of a diff of two whole documents;
        tokens the proof tokens it carries."""
        with self._wlock:
            if ops is not None:
                ops, rows = self._internal_ops(ops)
                tokens = list(tokens or [])
            else:
                cur = self.load()
                doc, rows = self._internal(doc)
                ops, tokens = ops_between(cur, doc)
            if not ops:
                changed = self._write_visits(doc)
                return self.note({**entry, "visits": changed})
            entry = {**entry, "change_id": entry.get("change_id") or "C-" + secrets.token_hex(6)}
            kept = _without_visitors({k: entry[k] for k in LINK_ENTRY if k in entry})    # visits by id only
            answer = self._propose(ops, tokens, rows, kept)
            changed = self._write_visits(doc)
            seq = answer.get("duplicate", self.store.size() - 1)
            return self.note({**entry, "link": seq, "link_hash": answer["hash"],
                              **({"visits": changed} if changed else {})})

    def _write_visits(self, doc: dict) -> dict[str, str | None]:
        """The desk's own side tables to match doc's visits: {visit id: digest of its bundle, None when erased}."""
        changed: dict[str, str | None] = {}
        before = {kind: dict(self.store.side_scan(kind)) for kind, _ in VISIT_KINDS}
        after = {kind: {r[field]: r for r in doc.get(kind) or []} for kind, field in VISIT_KINDS}
        for kind, _ in VISIT_KINDS:
            for key, rec in after[kind].items():
                if before[kind].get(key) != rec:
                    self.store.side_put(kind, key, rec)
                    vid = rec.get("visit_id", key)
                    changed[vid] = None
            for key in set(before[kind]) - set(after[kind]):
                self.store.side_delete(kind, key)
                changed.setdefault(before[kind][key].get("visit_id", key), None)
        for vid in changed:
            bundle = [r for kind, _ in VISIT_KINDS for r in after[kind].values() if r.get("visit_id") == vid]
            changed[vid] = _digest(bundle) if vid in after["visits"] else None
        if changed:
            self._gen += 1
        return changed

    def visit_ids(self) -> list[str]:
        return sorted(k for k, _ in self.store.side_scan("visits"))

    def erase_visits(self, vids: list[str], entry: dict) -> dict | None:
        """Erase visits past their retention from the side tables; the activity log keeps one line with their ids."""
        with self._wlock:
            vids = [v for v in vids if self.store.side_get("visits", v) is not None]
            if not vids:
                return None
            for kind, _ in VISIT_KINDS:
                for key, rec in list(self.store.side_scan(kind)):
                    if rec.get("visit_id", key) in vids:
                        self.store.side_delete(kind, key)
            self._gen += 1
            return self.note({**entry, "visits": {v: None for v in vids}})

    def close(self) -> None:
        try:
            self.store.close()
        finally:
            super().close()
