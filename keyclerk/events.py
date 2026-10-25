# SPDX-License-Identifier: EUPL-1.2
"""KeyClerk events, decision records and the timeline.

- keyclerk-event-v1: a CloudEvents 1.0 envelope (id UUIDv7, source, type keyclerk.<noun>.<verb>.v1, subject the entity
  id, time) whose data is one OCSF event plus the decision_id that caused it.
- The entity key: a person is person-pseudonym:<site>/<pseudonym>, the pseudonym a keyed hash of the anchor;
  events never carry more personal data than that.
- decision-record-v1: every KeyClerk decision writes one.
- The event log: append-only, idempotent by id, read through a cursor over (time, id) in both directions, with seek to
  a moment. Standalone this is a PostgreSQL table (SQLite stands in here with the same SQL); in a larger platform the same events
  go through NATS into the event store.
- state_at: what was true at a moment, derived from the records as of then (tools/access_state.py, historical mode),
  so browsing back shows state next to events without storing state.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone

TYPE = re.compile(r"^keyclerk\.[a-z][a-z-]*\.[a-z][a-z-]*\.v[0-9]+$")


def uuid7() -> str:
    if hasattr(uuid, "uuid7"):
        return str(uuid.uuid7())
    ms = int(time.time() * 1000)
    b = bytearray(ms.to_bytes(6, "big") + os.urandom(10))
    b[6] = (b[6] & 0x0F) | 0x70
    b[8] = (b[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))


def person_entity(key: bytes, anchor: str, site: str) -> str:
    """person-pseudonym:<site>/<pseudonym>: stable per tenant key, not reversible without it."""
    return f"person-pseudonym:{site}/" + hmac.new(key, anchor.encode(), hashlib.sha256).hexdigest()[:20]


def event(type_: str, subject: str, ocsf: dict, source: str, at: datetime, decision_id: str | None = None) -> dict:
    if not TYPE.match(type_):
        raise ValueError(f"event type {type_} is not keyclerk.<noun>.<verb>.v<n>")
    if not re.match(r"^[a-z-]+:[^/]+/.+$", subject):
        raise ValueError("subject must be an entity id (<kind>:<site>/<name>)")
    data = dict(ocsf)
    if decision_id:
        data["decision_id"] = decision_id
    return {"specversion": "1.0", "id": uuid7(), "source": source, "type": type_, "subject": subject,
            "time": at.astimezone(timezone.utc).isoformat(), "datacontenttype": "application/json", "data": data}


def decision_record(pdp: str, subject: dict, resource: dict, action: str, context: dict, result: str,
                    reasons: list[str], rule_ids: list[str], risks: list[str], at: datetime, trace_id: str = "") -> dict:
    """decision-record-v1: subject {entity_id, attributes used with source and age}, resource {entity_id,
    label, product}, action, context {purpose, lease, band, trust}, result, reasons, rule ids, risks, trace id."""
    for k in ("entity_id",):
        if k not in subject or k not in resource:
            raise ValueError("subject and resource need an entity_id")
    return {"schema": "decision-record-v1", "decision_id": uuid7(), "time": at.astimezone(timezone.utc).isoformat(),
            "pdp": pdp, "subject": subject, "resource": resource, "action": action, "context": context,
            "result": result, "reasons": reasons, "rule_ids": rule_ids, "risks": risks, "trace_id": trace_id}


class EventLog:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.execute("""CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, time TEXT NOT NULL, type TEXT NOT NULL,
                           subject TEXT NOT NULL, body TEXT NOT NULL)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS events_tid ON events (time, id)")

    def append(self, ev: dict) -> bool:
        """Idempotent by id: a second delivery of the same event is ignored (at-least-once delivery)."""
        try:
            self.db.execute("INSERT INTO events VALUES (?,?,?,?,?)",
                            (ev["id"], ev["time"], ev["type"], ev["subject"], json.dumps(ev, sort_keys=True)))
            return True
        except sqlite3.IntegrityError:
            return False

    @staticmethod
    def cursor(ev: dict) -> str:
        return f"{ev['time']}|{ev['id']}"

    def seek(self, at: datetime) -> str:
        """A cursor just before the first event at or after the moment."""
        return f"{at.astimezone(timezone.utc).isoformat()}|"

    def events(self, subject: str | None = None, type_prefix: str | None = None, after: str | None = None,
               before: str | None = None, limit: int = 50, since: datetime | None = None,
               until: datetime | None = None) -> list[dict]:
        """A page in time order. after: the page following that cursor; before: the page preceding it (still returned
        in time order), so a viewer moves back and forward without gaps or repeats."""
        where, args = [], []
        if subject:
            where.append("subject = ?")
            args.append(subject)
        if type_prefix:
            where.append("type LIKE ?")
            args.append(type_prefix + "%")
        if since:
            where.append("time >= ?")
            args.append(since.astimezone(timezone.utc).isoformat())
        if until:
            where.append("time < ?")
            args.append(until.astimezone(timezone.utc).isoformat())
        if after is not None:
            t, i = after.split("|", 1)
            where.append("(time > ? OR (time = ? AND id > ?))")
            args += [t, t, i]
        order = "ASC"
        if before is not None:
            t, i = before.split("|", 1)
            where.append("(time < ? OR (time = ? AND id < ?))")
            args += [t, t, i]
            order = "DESC"
        sql = "SELECT body FROM events" + (" WHERE " + " AND ".join(where) if where else "") + \
              f" ORDER BY time {order}, id {order} LIMIT ?"
        rows = [json.loads(b) for (b,) in self.db.execute(sql, args + [limit])]
        return rows[::-1] if order == "DESC" else rows


def state_at(doc: dict, anchor: str, at: datetime) -> list[dict]:
    """What the person held at that moment, derived from the records as of then (historical revocations)."""
    from keyclerk.access_state import grant_state
    out = []
    for g in doc.get("grants", []):
        if g["subject"]["anchor"] == anchor:
            s = grant_state(g, doc, at, historical=True)
            out.append({"grant_id": g["grant_id"], "role": g["role"], "class": g["class"], **{k: s[k] for k in ("intent", "validity", "effective")}})
    return out
