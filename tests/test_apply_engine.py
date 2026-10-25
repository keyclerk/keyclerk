# SPDX-License-Identifier: EUPL-1.2
"""KeyClerk engine step 2: queues, fenced apply, takeover, approvals at apply
time and the reduction journal. A Hypothesis state machine runs two reconcilers against one target with random
leases, pauses and work, and checks that no write ever comes from an epoch that does not hold the lease."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
from keyclerk import apply_engine as E  # noqa: E402
from keyclerk import records  # noqa: E402

T0 = datetime(2026, 10, 21, 9, 0, tzinfo=timezone.utc)
KEY = b"test-journal-key"


class FakeTarget:
    """A stand-in for Keycloak that records which epoch made each write."""

    def __init__(self, store):
        self.store, self.members, self.writes = store, set(), []

    def _check(self, epoch):
        holder = self.store.current("t")
        self.writes.append((epoch, holder[1] if holder else None))

    def add(self, group, anchor, epoch):
        self._check(epoch)
        self.members.add((group, anchor))

    def remove(self, group, anchor, epoch):
        self._check(epoch)
        self.members.discard((group, anchor))


def setup():
    s = E.Store()
    tgt = FakeTarget(s)
    return s, tgt, E.Journal(KEY)


def test_reductions_go_first_and_only_widenings_wait():
    s, tgt, j = setup()
    r = E.Reconciler("t", "a", s, tgt, j)
    assert r.lead(T0)
    s.enqueue("t", {"op": "add", "group": "/grants/x", "anchor": "p1"}, T0)
    s.enqueue("t", {"op": "remove", "group": "/grants/y", "anchor": "p1", "kind": "revocation", "grant_id": "G-t-0001"}, T0)
    s.enqueue("t", {"op": "add", "group": "/grants/z", "anchor": "p2", "kind": "leaver"}, T0)   # a leaver disguised as a change
    assert r.run(T0) == ["applied", "applied"]                   # the revocation and the leaver, not the widening
    assert ("/grants/x", "p1") not in tgt.members
    later = T0 + E.DEBOUNCE + timedelta(seconds=1)
    with pytest.raises(E.LostLease):
        r.run(later)                                             # its 15 s lease lapsed: fenced, nothing written
    assert r.lead(later) and r.run(later) == ["applied"]          # renewed, as every cycle does
    assert ("/grants/x", "p1") in tgt.members
    assert j.verify() == [] and j.revoked_ids() == {"G-t-0001"}


def test_a_stale_leader_can_never_write():
    s, tgt, j = setup()
    a, b = E.Reconciler("t", "a", s, tgt, j), E.Reconciler("t", "b", s, tgt, j)
    assert a.lead(T0) and not b.lead(T0)                         # one leader at a time
    later = T0 + E.LEASE + timedelta(seconds=1)                   # a was paused past its lease
    assert b.lead(later)
    with pytest.raises(E.LostLease):
        a.apply({"op": "add", "group": "/grants/x", "anchor": "p1"}, later)
    assert a.epoch is None and all(e == cur for e, cur in tgt.writes)


def test_takeover_rediffs_what_the_previous_epoch_touched():
    s, tgt, j = setup()
    a, b = E.Reconciler("t", "a", s, tgt, j), E.Reconciler("t", "b", s, tgt, j)
    a.lead(T0)
    a.apply({"op": "add", "group": "/grants/x", "anchor": "p1"}, T0)
    later = T0 + E.LEASE + timedelta(seconds=1)
    b.lead(later)
    assert [op["anchor"] for _, op in s.due("t", later, E.REDUCTION) if op["op"] == "rediff"] == ["p1"]


def test_an_approval_is_rechecked_at_apply_time():
    s, tgt, j = setup()
    r = E.Reconciler("t", "a", s, tgt, j)
    r.lead(T0)
    op = {"op": "add", "group": "/grants/x", "anchor": "p1",
          "approval": {"record_hash": "h1", "base_version": 7, "not_after": (T0 + timedelta(hours=1)).isoformat()}}
    ok = lambda o, now: E.approval_holds(o, now, "h1", 7)
    assert r.apply(op, T0, ok) == "applied"
    stale = lambda o, now: E.approval_holds(o, now, "h2", 7)      # the record changed since approval
    assert r.apply(op, T0, stale).startswith("refused")
    expired = T0 + timedelta(hours=2)
    r.lead(expired)
    assert r.apply(op, expired, ok).startswith("refused")


def test_the_journal_is_chained_signed_and_unioned_into_the_records(tmp_path):
    j = E.Journal(KEY)
    j.append({"op": "remove", "kind": "revocation", "grant_id": "G-example-0001", "anchor": "idp:7c1f-ann"}, T0)
    j.append({"op": "remove", "kind": "leaver", "anchor": "idp:91d0-bert"}, T0)
    assert j.verify() == []
    j.entries[0]["entry"]["grant_id"] = "G-example-0002"           # tampering is found
    assert j.verify()
    j.entries[0]["entry"]["grant_id"] = "G-example-0001"
    doc = records.load(FIXTURES / "records.yaml")
    merged = E.union_revocations(doc, j)
    assert {r["grant_id"] for r in merged["revocations"]} == {"G-example-0001", "G-example-0005"}
    assert records.guard(doc, merged) == []                        # the union only ever adds revocations


def test_events_are_consumed_once():
    s = E.Store()
    assert not s.seen("evt-1", T0) and s.seen("evt-1", T0)


class TwoReconcilers(RuleBasedStateMachine):
    @initialize()
    def start(self):
        self.store, self.target, self.journal = setup()
        self.now = T0
        self.r = {n: E.Reconciler("t", n, self.store, self.target, self.journal) for n in ("a", "b")}

    @rule(who=st.sampled_from(["a", "b"]))
    def lead(self, who):
        self.r[who].lead(self.now)

    @rule(seconds=st.integers(1, 40))
    def tick(self, seconds):
        self.now += timedelta(seconds=seconds)

    @rule(who=st.sampled_from(["a", "b"]), anchor=st.sampled_from(["p1", "p2", "p3"]), add=st.booleans())
    def act(self, who, anchor, add):
        op = {"op": "add" if add else "remove", "group": "/grants/g", "anchor": anchor}
        if not add:
            op["kind"] = "revocation"
        try:
            self.r[who].apply(op, self.now)
        except E.LostLease:
            pass

    @invariant()
    def every_write_comes_from_the_current_epoch(self):
        for epoch, current in getattr(self, "target", FakeTarget(None)).writes if hasattr(self, "target") else []:
            assert epoch == current

    @invariant()
    def the_journal_stays_intact(self):
        if hasattr(self, "journal"):
            assert self.journal.verify() == []


TwoReconcilers.TestCase.settings = settings(max_examples=120, stateful_step_count=40, deadline=None, database=None,
                                            suppress_health_check=[HealthCheck.too_slow])
test_no_stale_epoch_ever_writes_under_random_schedules = TwoReconcilers.TestCase
