# SPDX-License-Identifier: EUPL-1.2
"""What the desk keeps for edges outside the signed records (decision 0014): each edge's ceiling and state, the relay of
ciphertexts to person keys, escrowed break-glass ciphertexts, incidents and the evidence chain. Files under the desk's
store, written atomically, bounded; nothing here can decrypt anything it holds.
"""
from __future__ import annotations

import json
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from keyclerk import edge as E

RELAY_DAYS = 7                 # a relayed ciphertext waits at most this long (a lease credential: until its lease ends)
RELAY_PER_EDGE_PERSON = 10     # per (edge, person): one edge cannot fill a person's inbox
EVIDENCE_BATCH = 500
INCIDENT_KINDS = ("break_glass_used", "drift", "evidence_floor", "bind_without_session", "other")
CORE_INCIDENTS = ("officer_not_independent", "attestation_changed", "evidence_fork", "edge_silent", "phoned_unlock",
                  "carried_lease", "attestation_failed")   # raised by the desk


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(obj, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def _read(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


class EdgeStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.lock = threading.RLock()
        (self.root / "edges").mkdir(parents=True, exist_ok=True)
        (self.root / "relay").mkdir(parents=True, exist_ok=True)

    def _dir(self, edge_id: str) -> Path:
        if not E.EDGE_ID.fullmatch(edge_id):
            raise ValueError("not an edge id")
        return self.root / "edges" / edge_id

    # --- ceiling and state ---------------------------------------------------------------------------------------

    def ceiling(self, edge_id: str) -> tuple[dict | None, dict | None]:
        """(what the ceiling says, the officer's sealed ceiling as sent): verified when it was set (desk.set_ceiling)."""
        from keyclerk import edge as E
        c = _read(self._dir(edge_id) / "ceiling.json", None)
        if not c or "sealed" not in c:                 # a kc-edge-ceiling-v1 file: no migration (amendment 0014d)
            return None, None
        return E.opened(c["sealed"]), c["sealed"]

    def set_ceiling(self, edge_id: str, sealed: dict) -> None:
        with self.lock:
            _atomic(self._dir(edge_id) / "ceiling.json", {"sealed": sealed})

    def state(self, edge_id: str) -> dict:
        return _read(self._dir(edge_id) / "state.json", {"serial": 0})

    def update_state(self, edge_id: str, **changes) -> dict:
        with self.lock:
            s = {**self.state(edge_id), **changes}
            _atomic(self._dir(edge_id) / "state.json", s)
            return s

    def next_serial(self, edge_id: str) -> int:
        with self.lock:
            s = self.state(edge_id)
            n = int(s.get("serial", 0)) + 1
            self.update_state(edge_id, serial=n, last_pull=_iso(_now()))
            return n

    # --- the relay ------------------------------------------------------------------------------------------------

    def relay_room(self, edge_id: str, anchors: list[str]) -> bool:
        items = self.relay_items()
        return all(sum(1 for x in items if x["anchor"] == a and x["edge"] == edge_id) < RELAY_PER_EDGE_PERSON for a in anchors)

    def relay_put(self, edge_id: str, anchor: str, key_id: str, envelope: dict, purpose: str, expires: datetime | None = None,
                  keep: bool = False) -> str:
        """keep: an escrow half, never swept; it stays until its custodian confirms they opened it."""
        with self.lock:
            self.relay_sweep()
            if not self.relay_room(edge_id, [anchor]):
                raise ValueError(f"{RELAY_PER_EDGE_PERSON} ciphertexts from this edge already wait for that person")
            rid = "RL-" + secrets.token_hex(8)
            now = _now()
            end = min(expires or now + timedelta(days=RELAY_DAYS), now + timedelta(days=RELAY_DAYS))
            _atomic(self.root / "relay" / f"{rid}.json", {"relay_id": rid, "edge": edge_id, "anchor": anchor, "key_id": key_id,
                                                          "envelope": envelope, "purpose": purpose, "created": _iso(now),
                                                          "expires": None if keep else _iso(end), "keep": keep,
                                                          "taken": None, "confirmed": None})
            return rid

    def relay_items(self) -> list[dict]:
        return [x for x in (_read(f, None) for f in sorted((self.root / "relay").glob("RL-*.json"))) if x]

    def relay_take(self, rid: str) -> dict | None:
        """Hand a ciphertext over: it stays until its person confirms they opened it (or it expires), so a failed
        decryption in a browser never destroys it."""
        if not rid.startswith("RL-") or not rid[3:].isalnum():
            return None
        with self.lock:
            f = self.root / "relay" / f"{rid}.json"
            item = _read(f, None)
            if item is not None and not item.get("taken"):
                item["taken"] = _iso(_now())
                _atomic(f, item)
            return item

    def relay_confirm(self, rid: str) -> dict | None:
        """The person opened it: a relayed credential goes; an escrow half is marked confirmed, then goes."""
        if not rid.startswith("RL-") or not rid[3:].isalnum():
            return None
        with self.lock:
            f = self.root / "relay" / f"{rid}.json"
            item = _read(f, None)
            if item is None:
                return None
            f.unlink(missing_ok=True)
            item["confirmed"] = _iso(_now())
            if item.get("keep"):
                done = self.root / "relay-confirmed"
                done.mkdir(exist_ok=True)
                _atomic(done / f"{rid}.json", {k: v for k, v in item.items() if k != "envelope"})
            return item

    def confirmed(self, rid: str) -> dict | None:
        return _read(self.root / "relay-confirmed" / f"{rid}.json", None)

    def relay_sweep(self) -> None:
        now = _iso(_now())
        for x in self.relay_items():
            if x.get("expires") and x["expires"] < now:
                (self.root / "relay" / f"{x['relay_id']}.json").unlink(missing_ok=True)

    # --- escrow, incidents, evidence ----------------------------------------------------------------------------

    def escrow_put(self, edge_id: str, item: dict) -> None:
        with self.lock:
            _atomic(self._dir(edge_id) / "escrow" / f"{item['item_id']}.json", item)

    def escrow_get(self, edge_id: str, item_id: str) -> dict | None:
        if not item_id.replace("-", "").isalnum():
            return None
        return _read(self._dir(edge_id) / "escrow" / f"{item_id}.json", None)

    def evidence_line(self, edge_id: str, seq: int) -> dict | None:
        f = self._dir(edge_id) / "evidence.jsonl"
        if not f.exists() or seq < 1:
            return None
        with f.open(encoding="utf-8") as h:
            for i, line in enumerate(h, 1):
                if i == seq:
                    return json.loads(line)
        return None

    INCIDENTS_PER_HOUR = 60
    INCIDENTS_KEPT = 5000

    def incident(self, edge_id: str, rec: dict, core: bool = False) -> dict:
        """An incident; an edge may report at most 60 an hour (the core's own always count), and the file keeps the
        newest 5000."""
        from keyclerk import metrics
        metrics.inc("keyclerk_edge_incidents_total", kind=str(rec.get("kind") or "other"))
        with self.lock:
            f = self._dir(edge_id) / "incidents.jsonl"
            f.parent.mkdir(parents=True, exist_ok=True)
            past = self.incidents(edge_id, limit=self.INCIDENTS_KEPT)
            hour_ago = _iso(_now() - timedelta(hours=1))
            if not core and sum(1 for x in past if x["received"] >= hour_ago and not x.get("core")) >= self.INCIDENTS_PER_HOUR:
                raise ValueError(f"more than {self.INCIDENTS_PER_HOUR} incidents from this edge in an hour")
            rec = {"incident_id": "IN-" + secrets.token_hex(6), "edge": edge_id, "received": _iso(_now()), **rec,
                   **({"core": True} if core else {})}
            lines = [json.dumps(x, sort_keys=True) for x in past[-(self.INCIDENTS_KEPT - 1):]] + [json.dumps(rec, sort_keys=True)]
            tmp = f.with_name(f.name + ".tmp")
            tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
            os.replace(tmp, f)
            return rec

    def close_incident(self, edge_id: str, incident_id: str, by: str, note: str) -> dict | None:
        with self.lock:
            items = self.incidents(edge_id, limit=self.INCIDENTS_KEPT)
            hit = next((x for x in items if x["incident_id"] == incident_id), None)
            if hit is None:
                return None
            hit.update(closed=_iso(_now()), closed_by=by, close_note=note)
            f = self._dir(edge_id) / "incidents.jsonl"
            tmp = f.with_name(f.name + ".tmp")
            tmp.write_text("\n".join(json.dumps(x, sort_keys=True) for x in items) + "\n", encoding="utf-8")
            os.replace(tmp, f)
            return hit

    def incidents(self, edge_id: str, limit: int = 200) -> list[dict]:
        f = self._dir(edge_id) / "incidents.jsonl"
        if not f.exists():
            return []
        return [json.loads(x) for x in f.read_text(encoding="utf-8").splitlines()[-limit:] if x.strip()]

    def evidence_head(self, edge_id: str) -> tuple[int, str]:
        s = self.state(edge_id)
        return int(s.get("evidence_seq", 0)), str(s.get("evidence_head", "0" * 64))

    def evidence_add(self, edge_id: str, entries: list[dict]) -> tuple[int, str]:
        """Entries continue the chain: seq one higher each, prev the hash of the previous entry (canonical JSON)."""
        with self.lock:
            seq, head = self.evidence_head(edge_id)
            fresh = []
            for e in entries:                        # a resend after a lost acknowledgement: the same entry is no change
                if isinstance(e.get("seq"), int) and e["seq"] <= seq and self.evidence_line(edge_id, e["seq"]) == e:
                    continue
                fresh.append(e)
            entries = fresh
            for e in entries:
                if e.get("seq") != seq + 1 or e.get("prev") != head:
                    raise ValueError(f"the chain breaks at seq {e.get('seq')}: expected seq {seq + 1} after {head[:12]}")
                head, seq = E.sha256(E.canonical(e)), seq + 1
            d = self._dir(edge_id)
            d.mkdir(parents=True, exist_ok=True)
            with (d / "evidence.jsonl").open("a", encoding="utf-8") as h:
                for e in entries:
                    h.write(json.dumps(e, sort_keys=True) + "\n")
            self.update_state(edge_id, evidence_seq=seq, evidence_head=head)
            return seq, head
