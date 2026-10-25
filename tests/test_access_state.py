# SPDX-License-Identifier: EUPL-1.2
"""KeyClerk engine step 1: records one file each with a history guard, and state derived
from records and time. A Hypothesis rule-based state machine drives random histories (grant, revoke, suspend, lift,
move time) and checks the invariants after every step."""
import copy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
from keyclerk import access_state as S  # noqa: E402
from keyclerk import grants  # noqa: E402
from keyclerk import leases  # noqa: E402
from keyclerk import records  # noqa: E402

DEMO = FIXTURES / "records.yaml"
T0 = datetime(2026, 10, 21, 9, 0, tzinfo=timezone.utc)


def test_records_round_trip_and_history_guard(tmp_path):
    doc = records.load(DEMO)
    records.split(doc, tmp_path / "realm")
    back = records.load(tmp_path / "realm")
    assert back == doc   # one file per record holds exactly the same realm
    full = copy.deepcopy(doc)                     # and so does every kind added since (approvers, proofs, the serial)
    full["approvers"] = [{"approver_id": "A-1", "anchor": "idp:bb11-kai", "appointed_by": "idp:2b9e-owner",
                          "approved_by": ["idp:31ee-ingrid"], "from": T0, "to": T0}]
    full["approval_proofs"] = [{"records": ["A-1"], "by": "idp:31ee-ingrid", "token": "t"}]
    full["revision"] = 7
    records.split(full, tmp_path / "realm-full")
    assert records.load(tmp_path / "realm-full") == full
    assert grants.check(back, grants.rules()) == [] and leases.check(back, leases.rules()) == []
    assert (tmp_path / "realm" / "revocations" / "G-example-0005.yaml").is_file()
    # a new head may add, never drop or change a revocation, and never reuse a revoked id
    dropped = copy.deepcopy(doc)
    dropped["revocations"] = []
    assert any("revocation dropped" in e for e in records.guard(doc, dropped))
    changed = copy.deepcopy(doc)
    changed["revocations"][0]["reason"] = "typo"
    assert any("revocation changed" in e for e in records.guard(doc, changed))
    assert records.guard(doc, doc) == []
    # a mismatched file name is refused
    bad = tmp_path / "realm" / "grants" / "G-example-0001.yaml"
    bad.rename(bad.with_name("G-example-9999.yaml"))
    with pytest.raises(ValueError):
        records.load(tmp_path / "realm")


def test_effective_status_never_outlives_the_end_and_revocation_wins():
    doc = records.load(DEMO)
    g = next(x for x in doc["grants"] if x["grant_id"] == "G-example-0003")   # activation 08:00-12:00
    assert S.grant_state(g, doc, T0)["effective"] == "active"
    assert S.grant_state(g, doc, datetime(2026, 10, 21, 12, tzinfo=timezone.utc))["effective"] == "ended"
    r = next(x for x in doc["grants"] if x["grant_id"] == "G-example-0005")
    assert S.grant_state(r, doc, T0)["effective"] == "revoked"


def test_skew_only_narrows():
    doc = records.load(DEMO)
    g = next(x for x in doc["grants"] if x["grant_id"] == "G-example-0003")
    end = grants._ts(g["end"])
    near = end - timedelta(seconds=10)   # inside the skew window before the end
    assert S.grant_state(g, doc, near)["effective"] == "active"
    assert not S.may_widen(g, doc, near) and S.must_reduce(g, doc, near)
    start = grants._ts(g["start"])
    assert not S.may_widen(g, doc, start + timedelta(seconds=10))   # not yet sure it has started


def test_suspension_needs_two_people_to_lift():
    doc = records.load(DEMO)
    doc["suspensions"] = [{"suspension_id": "S-1", "anchor": "idp:7c1f-ann", "at": "2026-10-21T08:30:00Z", "by": "officer:1",
                           "lifted": {"at": "2026-10-21T08:40:00Z", "by": ["officer:1", "owner:1"]}}]
    assert S.suspended(doc, "idp:7c1f-ann", T0)   # the suspender cannot be one of the two lifters
    doc["suspensions"][0]["lifted"]["by"] = ["owner:1", "auditor:1"]
    assert not S.suspended(doc, "idp:7c1f-ann", T0)


def test_admin_persona_lives_only_with_an_eligibility_and_wake_is_bounded():
    doc = records.load(DEMO)
    assert S.persona_state(doc, "idp:7c1f-ann", "admin", T0) == "active"
    assert S.persona_state(doc, "idp:7c1f-ann", "admin", datetime(2027, 1, 2, tzinfo=timezone.utc)) == "blocked"
    assert S.persona_state(doc, "idp:91d0-bert", "admin", T0) == "absent"
    nxt = S.next_boundary(doc, T0, leases.rules())
    assert T0 < nxt <= T0 + S.MAX_WAKE


ANCHORS = ["a1", "a2", "a3"]


class Lifecycle(RuleBasedStateMachine):
    """Random histories over one realm; every invariant must hold after every step."""

    @initialize()
    def start(self):
        self.now = T0
        self.doc = {"realm": "t", "grants": [], "revocations": [], "suspensions": []}
        self.n = 0
        self.revoked_ever = set()

    @rule(anchor=st.sampled_from(ANCHORS), start_h=st.integers(-48, 48), hours=st.integers(1, 200),
          cls=st.sampled_from(["functional", "eligibility"]))
    def grant(self, anchor, start_h, hours, cls):
        self.n += 1
        s = self.now + timedelta(hours=start_h)
        self.doc["grants"].append({
            "grant_id": f"G-t-{self.n:04d}", "subject": {"anchor": anchor, "kind": "tenant", "persona": "admin" if cls == "eligibility" else "person"},
            "role": "tenant-admin" if cls == "functional" else "tenant-admin-privileged", "plane": "tenant", "class": cls,
            "scope": {"level": "tenant", "id": "t"}, "label_ceiling": "Internal", "justification": {"f": "x"},
            "requested_by": "req", "approved_by": ["appr"], "start": s.isoformat(), "end": (s + timedelta(hours=hours)).isoformat()})

    @rule(i=st.integers(0, 50))
    def revoke(self, i):
        live = [g for g in self.doc["grants"] if g["grant_id"] not in self.revoked_ever]
        if live:
            gid = live[i % len(live)]["grant_id"]
            self.doc["revocations"].append({"grant_id": gid, "at": self.now.isoformat(), "by": "home", "reason": "test"})
            self.revoked_ever.add(gid)

    @rule(anchor=st.sampled_from(ANCHORS))
    def suspend(self, anchor):
        self.n += 1
        self.doc["suspensions"].append({"suspension_id": f"S-{self.n}", "anchor": anchor, "at": self.now.isoformat(), "by": "officer"})

    @rule(i=st.integers(0, 50), lifters=st.lists(st.sampled_from(["officer", "owner", "auditor"]), min_size=1, max_size=2, unique=True))
    def lift(self, i, lifters):
        open_ = [s for s in self.doc["suspensions"] if "lifted" not in s]
        if open_:
            open_[i % len(open_)]["lifted"] = {"at": self.now.isoformat(), "by": lifters}

    @rule(minutes=st.integers(1, 6000))
    def tick(self, minutes):
        self.before = {g["grant_id"]: S.grant_state(g, self.doc, self.now)["effective"] for g in self.doc["grants"]}
        self.now += timedelta(minutes=minutes)

    @invariant()
    def nothing_outlives_its_end(self):
        for g in getattr(self, "doc", {}).get("grants", []):
            st_ = S.grant_state(g, self.doc, self.now)
            if self.now >= grants._ts(g["end"]):
                assert st_["effective"] in ("ended", "revoked")

    @invariant()
    def revocation_wins_forever(self):
        for g in getattr(self, "doc", {}).get("grants", []):
            if g["grant_id"] in getattr(self, "revoked_ever", set()):
                assert S.grant_state(g, self.doc, self.now)["effective"] == "revoked"
                assert not S.may_widen(g, self.doc, self.now)

    @invariant()
    def widening_implies_active_on_both_sides_of_the_skew(self):
        for g in getattr(self, "doc", {}).get("grants", []):
            if S.may_widen(g, self.doc, self.now):
                assert S.grant_state(g, self.doc, self.now)["effective"] == "active"
                assert not S.suspended(self.doc, g["subject"]["anchor"], self.now)

    @invariant()
    def time_never_revives(self):
        for gid, prev in getattr(self, "before", {}).items():
            if prev in ("ended", "revoked"):
                g = next(x for x in self.doc["grants"] if x["grant_id"] == gid)
                assert S.grant_state(g, self.doc, self.now)["effective"] in ("ended", "revoked")

    @invariant()
    def admin_persona_only_with_eligibility(self):
        for a in ANCHORS:
            if getattr(self, "doc", None) and S.persona_state(self.doc, a, "admin", self.now) == "active":
                assert any(g["subject"]["anchor"] == a and g["class"] == "eligibility" and S.may_widen(g, self.doc, self.now)
                           for g in self.doc["grants"])

    @invariant()
    def plan_adds_only_effective_grants(self):
        if not getattr(self, "doc", None):
            return
        p = grants.plan(self.doc, {}, self.now)
        ok = {(grants.group_of(g), g["subject"]["anchor"]) for g in S.effective_grants(self.doc, self.now)}
        assert all((x["group"], x["anchor"]) in ok for x in p["add"])


Lifecycle.TestCase.settings = settings(max_examples=150, stateful_step_count=40, deadline=None, database=None,
                                       suppress_health_check=[HealthCheck.too_slow])
test_lifecycle_invariants_hold_under_random_histories = Lifecycle.TestCase


def test_every_top_level_kind_of_the_records_survives_a_split():
    import json
    schema = json.loads((ROOT / "keyclerk" / "schema" / "records.schema.json").read_text(encoding="utf-8"))
    assert set(schema["properties"]) <= set(records.HEAD) | set(records.KINDS)
