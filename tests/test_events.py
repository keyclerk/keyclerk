# SPDX-License-Identifier: EUPL-1.2
"""KeyClerk events and timeline: the envelope, the pseudonymous entity key, decision
records, an idempotent event log browsed in both directions, and state at a moment that never rewrites the past."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
from keyclerk import events as K  # noqa: E402
from keyclerk import records  # noqa: E402

T0 = datetime(2026, 10, 21, 9, 0, tzinfo=timezone.utc)
KEY = b"tenant-pseudonym-key"


def test_the_envelope_and_the_entity_key():
    who = K.person_entity(KEY, "idp:7c1f-ann", "heverlee")
    assert who.startswith("person-pseudonym:heverlee/") and "ann" not in who
    assert K.person_entity(KEY, "idp:7c1f-ann", "heverlee") == who != K.person_entity(b"other", "idp:7c1f-ann", "heverlee")
    ev = K.event("keyclerk.grant.added.v1", who, {"class_uid": 3006, "activity_id": 1}, "keyclerk/example", T0, "d-1")
    assert ev["specversion"] == "1.0" and ev["data"]["decision_id"] == "d-1" and ev["id"][14] == "7"   # UUIDv7
    with pytest.raises(ValueError):
        K.event("grant.added", who, {}, "s", T0)
    with pytest.raises(ValueError):
        K.event("keyclerk.grant.added.v1", "Ann Peeters", {}, "s", T0)       # a name is never a subject


def test_a_decision_record_has_the_shape_of_adr_0154():
    who = K.person_entity(KEY, "idp:7c1f-ann", "heverlee")
    d = K.decision_record("keyclerk-pdp", {"entity_id": who, "attributes": [{"name": "unit", "source": "scim", "age_s": 30}]},
                          {"entity_id": "service:heverlee/renovation-share", "label": "Internal"}, "activate",
                          {"band": "green", "trust": {"identity": "medium"}}, "allow", [], ["keyclerk.access.activate"], ["RI-11"], T0)
    assert d["schema"] == "decision-record-v1" and d["result"] == "allow" and d["decision_id"]


def test_events_are_appended_once():
    log = K.EventLog()
    ev = K.event("keyclerk.door.entry.v1", "person-pseudonym:h/x", {"class_uid": 3002}, "s", T0)
    assert log.append(ev) and not log.append(ev)


@settings(max_examples=60, deadline=None, database=None)
@given(st.lists(st.integers(0, 50), min_size=1, max_size=40), st.integers(1, 7))
def test_paging_forward_and_back_never_skips_or_repeats(offsets, page):
    log = K.EventLog()
    evs = [K.event("keyclerk.door.entry.v1", "person-pseudonym:h/x", {"n": i}, "s", T0 + timedelta(minutes=o))
           for i, o in enumerate(offsets)]
    for e in evs:
        log.append(e)
    expected = sorted(evs, key=lambda e: (e["time"], e["id"]))
    seen, cur = [], None
    while True:
        p = log.events(after=cur, limit=page) if cur else log.events(limit=page)
        if not p:
            break
        seen += p
        cur = K.EventLog.cursor(p[-1])
    assert [e["id"] for e in seen] == [e["id"] for e in expected]          # forward: every event once, in order
    back, cur = [], K.EventLog.cursor(seen[-1])
    back = [seen[-1]]
    while True:
        p = log.events(before=cur, limit=page)
        if not p:
            break
        back = p + back
        cur = K.EventLog.cursor(p[0])
    assert [e["id"] for e in back] == [e["id"] for e in expected]          # back: the same sequence


def test_seek_and_filters():
    log = K.EventLog()
    for h, t in ((0, "keyclerk.door.entry.v1"), (2, "keyclerk.grant.added.v1"), (4, "keyclerk.door.exit.v1")):
        log.append(K.event(t, "person-pseudonym:h/x", {}, "s", T0 + timedelta(hours=h)))
    page = log.events(after=log.seek(T0 + timedelta(hours=1)), limit=10)
    assert [e["type"] for e in page] == ["keyclerk.grant.added.v1", "keyclerk.door.exit.v1"]
    assert [e["type"] for e in log.events(type_prefix="keyclerk.door.")] == ["keyclerk.door.entry.v1", "keyclerk.door.exit.v1"]


def test_state_at_a_moment_never_rewrites_the_past():
    doc = records.load(FIXTURES / "records.yaml")   # G-example-0005 revoked 2026-10-15 09:12
    before = {s["grant_id"]: s["effective"] for s in K.state_at(doc, "idp:91d0-bert", datetime(2026, 10, 10, tzinfo=timezone.utc))}
    after = {s["grant_id"]: s["effective"] for s in K.state_at(doc, "idp:91d0-bert", datetime(2026, 10, 16, tzinfo=timezone.utc))}
    assert before["G-example-0005"] == "active" and after["G-example-0005"] == "revoked"
