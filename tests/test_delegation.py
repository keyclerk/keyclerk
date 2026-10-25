# SPDX-License-Identifier: EUPL-1.2
"""Delegated administration and nested groups: authority is a chain to the root role that
only narrows, nesting is flattened with its risk carried upwards, rules are re-checked now, and a revocation for cause
leaves nothing the person made or approved since the compromise."""
import copy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
from keyclerk import delegation as D  # noqa: E402
from keyclerk import records  # noqa: E402

DEMO = FIXTURES / "records.yaml"
NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
ANN, BERT, DIRK, OWNER, INGRID = "idp:7c1f-ann", "idp:91d0-bert", "idp:44aa-dirk", "idp:2b9e-owner", "idp:31ee-ingrid"


def demo() -> dict:
    return copy.deepcopy(records.load(DEMO))


def _m(doc, mid, group, member, by, under, start=NOW, days=30, **kw):
    doc["memberships"].append({"membership_id": mid, "group": group, "member": member, "by": by, "under": under,
                               "start": start.isoformat(), "end": (start + timedelta(days=days)).isoformat(), **kw})
    return doc["memberships"][-1]


def test_the_demo_tree_is_clean_and_explains_itself():
    doc = demo()
    assert D.check(doc) == []
    assert D.explain(doc, "idp:55bb-eva", "office-staff", NOW) == [
        ["office-staff", "site-heverlee", "M-example-0002", "under D-example-0002 < root"]]
    assert D.authority(doc, ANN, "finance", "members", NOW) == "D-example-0001"
    assert D.authority(doc, ANN, "site-wilsele", "members", NOW) is None          # outside her subtree
    assert D.authority(doc, BERT, "admins", "members", NOW) is None
    assert D.authority(doc, OWNER, "admins", "members", NOW) == "root"


def test_a_delegation_never_exceeds_its_parent():
    doc = demo()
    d3 = next(d for d in doc["delegations"] if d["delegation_id"] == "D-example-0003")
    for change, needle in (({"powers": ["members", "includes"]}, "powers wider"), ({"max_risk": "elevated"}, "max_risk above"),
                           ({"group": "office-staff"}, "outside the parent's subtree"), ({"depth_left": 1}, "depth_left"),
                           ({"end": "2027-06-01T00:00:00Z"}, "outlives"), ({"max_membership_days": 120}, "max_membership_days")):
        bad = {**d3, **change}
        assert any(needle in e for e in D.attenuation_errors(doc, bad)), change


def test_retire_keeps_what_was_made_for_the_grace_period_and_stops_the_deputy_at_once():
    doc = demo()   # D-0003 (Dirk) retired 2026-10-20 08:00
    finn = next(m for m in doc["memberships"] if m["membership_id"] == "M-example-0004")
    assert D.membership_status(doc, finn, NOW) == "active"
    assert D.membership_status(doc, finn, datetime(2026, 11, 3, 9, tzinfo=timezone.utc)) == "lapsed"
    assert D.authority(doc, DIRK, "site-wilsele", "members", NOW) is None


def test_revoke_for_cause_voids_everything_made_since_the_compromise_whatever_delegation_it_used():
    doc = demo()
    m = _m(doc, "M-x1", "office-staff", {"anchor": "idp:66cc-finn"}, ANN, "D-example-0001", start=NOW - timedelta(hours=2))
    doc["admin_revocations"].append({"id": "D-example-0001", "at": NOW.isoformat(), "by": OWNER, "mode": "revoke",
                                     "from": (NOW - timedelta(hours=3)).isoformat(), "reason": "phished"})
    assert D.membership_status(doc, m, NOW) == "void"
    gina = next(x for x in doc["memberships"] if x["membership_id"] == "M-example-0005")
    assert D.membership_status(doc, gina, NOW) == "lapsed"                          # made before, under the dead chain
    assert D.authority(doc, ANN, "office-staff", "members", NOW) is None


def test_root_succession_does_not_cascade_but_a_compromised_root_voids_its_later_delegations():
    doc = demo()
    doc["root"]["holders"][0]["to"] = "2026-10-21T00:00:00Z"
    doc["root"]["holders"].append({"anchor": INGRID, "appointed_by": "op:7a1e-oscar", "from": "2026-10-21T00:00:00Z"})
    assert D.authority(doc, ANN, "finance", "members", NOW) == "D-example-0001"   # made by the root of its time
    doc["admin_revocations"].append({"id": "root:" + OWNER, "at": NOW.isoformat(), "by": "op:7a1e-oscar",
                                     "mode": "revoke", "from": "2026-10-01T12:00:00Z"})
    assert D.authority(doc, ANN, "finance", "members", NOW) == "D-example-0001"   # made before the compromise
    doc["admin_revocations"][-1]["from"] = "2026-09-30T00:00:00Z"
    assert D.authority(doc, ANN, "finance", "members", NOW) is None


def test_a_group_carrying_more_than_its_fixed_class_fails_and_its_members_are_rechecked():
    doc = demo()
    staff = next(g for g in doc["groups"] if g["group_id"] == "office-staff")
    staff["carries"].append({"entitlement": "bookkeeping-approve", "by": OWNER})
    assert any("above its fixed class" in e for e in D.check(doc))


def test_an_include_carries_the_includers_risk_down():
    doc = demo()   # office-staff (low) includes site-heverlee (low)
    staff = next(g for g in doc["groups"] if g["group_id"] == "office-staff")
    staff["max_risk"] = "elevated"
    assert D.effective_risk(doc, "site-heverlee") == "elevated"
    assert D.authority(doc, BERT, "site-heverlee", "members", NOW) is None             # Bert's delegation allows low only
    inc = next(m for m in doc["memberships"] if m["membership_id"] == "M-example-0003")
    assert any("classed below" in e for e in D.membership_errors(doc, inc))


def test_include_rules_cycle_depth_privileged_control_and_self():
    doc = demo()
    cyc = _m(doc, "M-c", "site-heverlee", {"group": "office-staff"}, OWNER, "root")
    assert any("cycle" in e for e in D.membership_errors(doc, cyc))
    doc["memberships"].pop()
    priv = _m(doc, "M-p", "office-staff", {"group": "admins"}, OWNER, "root")
    assert any("privileged" in e for e in D.membership_errors(doc, priv))
    doc["memberships"].pop()
    ctl = _m(doc, "M-k", "office-staff", {"group": "site-wilsele"}, ANN, "D-example-0001")
    assert any("members power over site-wilsele" in e for e in D.membership_errors(doc, ctl))   # control
    doc["memberships"].pop()
    _m(doc, "M-s1", "site-wilsele", {"anchor": ANN}, BERT, "D-example-0002")
    selfinc = _m(doc, "M-s2", "office-staff", {"group": "site-wilsele"}, ANN, "D-example-0001", approved_by=[BERT])
    assert any("puts the actor into a group they manage" in e for e in D.membership_errors(doc, selfinc))


def test_depth_is_checked_for_every_including_ancestor():
    doc = demo()
    for gid in ("g1", "g2", "g3", "g4"):
        doc["groups"].append({"group_id": gid, "parent": "sites", "max_risk": "low", "carries": []})
    _m(doc, "M-d1", "office-staff", {"group": "g1"}, OWNER, "root")
    _m(doc, "M-d2", "g1", {"group": "g2"}, OWNER, "root")
    deep = _m(doc, "M-d3", "g2", {"group": "g3"}, OWNER, "root")   # office-staff > g1 > g2 > g3 is three below g... plus site-heverlee
    _m(doc, "M-d4", "g3", {"group": "g4"}, OWNER, "root")
    assert any("deeper" in e for e in D.membership_errors(doc, doc["memberships"][-1]))
    assert deep


def test_second_keys_come_from_outside_the_chain_and_never_from_the_person():
    doc = demo()
    m = _m(doc, "M-f", "finance", {"anchor": BERT}, ANN, "D-example-0001", approved_by=[OWNER])  # Bert is a deputy
    assert any("second key" in e for e in D.membership_errors(doc, m))                # the root is above the chain
    m["approved_by"] = [INGRID]
    assert not any("second key" in e for e in D.membership_errors(doc, m))
    doc["persons"].append({"person": "ann", "kind": "tenant", "anchors": ["idp:ann-second"]})
    m2 = _m(doc, "M-g", "office-staff", {"anchor": "idp:ann-second"}, ANN, "D-example-0001")
    assert any("themselves" in e for e in D.membership_errors(doc, m2))


def test_externals_and_agents_are_never_deputies_or_members():
    doc = demo()
    m = _m(doc, "M-e", "office-staff", {"anchor": "ext:3a71-carla"}, ANN, "D-example-0001")
    assert any("externals come through leases" in e for e in D.membership_errors(doc, m))
    d = {**doc["delegations"][2], "delegation_id": "D-agent", "delegate": "agent:helper"}
    assert any("tenant person" in e for e in D.attenuation_errors(doc, d))


def test_attribute_rules_match_only_fresh_values_from_their_source_and_never_on_privileged_groups():
    doc = demo()
    people = {"idp:88ee-hans": {"attributes": {"unit": {"value": "office", "source": "HR source", "at": NOW - timedelta(hours=2)}}},
              "idp:99ff-ida": {"attributes": {"unit": {"value": "office", "source": "self", "at": NOW}}},
              "idp:aa00-jan": {"attributes": {"unit": {"value": "office", "source": "HR source", "at": NOW - timedelta(days=3)}}}}
    doc["persons"] += [{"person": a, "kind": "tenant", "anchors": [a]} for a in people]
    members = D.effective_members(doc, "office-staff", NOW, people)
    assert "idp:88ee-hans" in members and not {"idp:99ff-ida", "idp:aa00-jan"} & members
    r = _m(doc, "M-r", "admins", {"rule": {"attribute": "unit", "values": ["office"], "source": "HR source", "max_age_hours": 24}},
           OWNER, "root", approved_by=[INGRID])
    assert any("named members only" in e for e in D.membership_errors(doc, r))
    r2 = _m(doc, "M-r2", "office-staff", {"rule": {"attribute": "nickname", "values": ["x"], "source": "HR source", "max_age_hours": 1}},
            ANN, "D-example-0001")
    assert any("not in the attribute registry" in e for e in D.membership_errors(doc, r2))


def test_sod_behind_an_include_is_found():
    doc = demo()
    doc["groups"].append({"group_id": "site-office", "parent": "sites", "max_risk": "elevated", "carries": []})
    _m(doc, "M-a", "payment-approvers", {"anchor": "idp:66cc-finn"}, ANN, "D-example-0001")
    _m(doc, "M-b", "site-office", {"anchor": "idp:66cc-finn"}, OWNER, "root")
    _m(doc, "M-c", "finance", {"group": "site-office"}, OWNER, "root")   # finn books through the include
    assert any(c["anchor"] == "idp:66cc-finn" and c["sod"] == "SOD-1" for c in D.sod_conflicts(doc, NOW))


def test_rate_caps_count_the_whole_subtree():
    doc = demo()
    for i in range(61):
        who = (ANN, "idp:77dd-gina")[i % 2]
        if who != ANN:
            continue
        _m(doc, f"M-rate-{i}", "office-staff", {"anchor": f"idp:p{i}"}, ANN, "D-example-0001")
    assert any("widenings" in e for e in D.check(doc))


def test_the_reconciler_writes_flat_groups_and_removes_what_lapsed():
    from keyclerk import grants
    doc = demo()
    plan = grants.plan(doc, {"/groups/site-wilsele": ["idp:66cc-finn", "idp:zz-stray"]}, datetime(2026, 11, 4, tzinfo=timezone.utc))
    adds = {(a["group"], a["anchor"]) for a in plan["add"]}
    assert ("/groups/office-staff", "idp:55bb-eva") in adds                           # flattened through the include
    gone = {(r["group"], r["anchor"]): r["why"] for r in plan["remove"]}
    assert gone[("/groups/site-wilsele", "idp:66cc-finn")] == "ended-or-revoked"      # Dirk's grace ran out
    assert gone[("/groups/site-wilsele", "idp:zz-stray")] == "undeclared"              # a finding


def test_the_bundle_data_holds_only_live_authority():
    data = D.opa_data(demo(), NOW)
    assert set(data["authority"]) == {OWNER, ANN, BERT}                                # Dirk is retired
    assert data["risk"]["admins"] == "privileged" and data["revision"] == 1

def test_attributes_widen_only_when_registered_to_and_derived_ones_only_on_low_groups():
    doc = demo()
    up = {"attribute": "upstream_group", "values": ["fin-team"], "source": "corporate IdP", "max_age_hours": 24}
    low = _m(doc, "M-u1", "office-staff", {"rule": up}, ANN, "D-example-0001")
    assert D.membership_errors(doc, low) == []
    high = _m(doc, "M-u2", "finance", {"rule": up}, ANN, "D-example-0001", approved_by=[INGRID])
    assert any("derived" in e for e in D.membership_errors(doc, high))
    narrow = _m(doc, "M-u3", "office-staff", {"rule": {"attribute": "location_class", "values": ["office"],
                                                       "source": "NetBird", "max_age_hours": 1}}, ANN, "D-example-0001")
    assert any("may only narrow" in e for e in D.membership_errors(doc, narrow))


# --- a state machine: whatever deputies do, no one acts beyond what root handed down, and revoke leaves nothing ----

GROUPS = ["office", "office-staff", "finance", "sites", "site-heverlee", "site-wilsele"]
PEOPLE = [ANN, BERT, DIRK, "idp:55bb-eva", "idp:66cc-finn", "idp:77dd-gina"]


class Deputies(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.doc = demo()
        self.doc["memberships"] = [m for m in self.doc["memberships"] if m["under"] == "root"]
        self.doc["delegations"] = [d for d in self.doc["delegations"] if d["parent"] == "root"]
        self.doc["admin_revocations"] = []
        self.t = NOW
        self.n = 0

    def _id(self, p):
        self.n += 1
        return f"{p}-{self.n}"

    @rule(by=st.sampled_from(PEOPLE), to=st.sampled_from(PEOPLE), group=st.sampled_from(GROUPS),
          powers=st.sets(st.sampled_from(sorted(D.POWERS)), min_size=1), risk=st.sampled_from(list(D.RISK)),
          days=st.integers(1, 200), depth=st.integers(0, 2))
    def delegate(self, by, to, group, powers, risk, days, depth):
        """Anyone may try; only an attenuated delegation by someone holding the delegate power is kept."""
        parent = D.authority(self.doc, by, group, "delegate", self.t)
        if parent is None:
            return
        d = {"delegation_id": self._id("D"), "delegate": to, "group": group, "powers": sorted(powers), "max_risk": risk,
             "max_membership_days": days, "depth_left": depth, "start": self.t.isoformat(),
             "end": (self.t + timedelta(days=days)).isoformat(), "by": by, "parent": parent}
        if parent == "root":
            d["approved_by"] = [INGRID]
        if not D.attenuation_errors(self.doc, d):
            self.doc["delegations"].append(d)

    @rule(by=st.sampled_from(PEOPLE), who=st.sampled_from(PEOPLE), group=st.sampled_from(GROUPS), days=st.integers(1, 200))
    def add(self, by, who, group, days):
        under = D.authority(self.doc, by, group, "members", self.t)
        if under is None:
            return
        m = _m(self.doc, self._id("M"), group, {"anchor": who}, by, under, start=self.t, days=days)
        if D.membership_errors(self.doc, m):
            self.doc["memberships"].pop()

    @rule(idx=st.integers(0, 50), mode=st.sampled_from(["retire", "revoke"]))
    def end(self, idx, mode):
        ds = self.doc["delegations"]
        if ds:
            d = ds[idx % len(ds)]
            self.doc["admin_revocations"].append({"id": d["delegation_id"], "at": self.t.isoformat(), "by": d["by"],
                                                  "mode": mode, "from": self.t.isoformat()})

    @rule(hours=st.integers(1, 24 * 20))
    def wait(self, hours):
        self.t += timedelta(hours=hours)

    @invariant()
    def no_one_acts_beyond_their_chain(self):
        for d in self.doc["delegations"]:
            if D.chain_status(self.doc, d["delegation_id"], self.t)[0] == "ok":
                for link in D.chain(self.doc, d["delegation_id"]):
                    assert D.attenuation_errors(self.doc, link) == []
                    assert self.t < D._ts(link["end"])                                # nothing outlives its parent

    @invariant()
    def every_active_membership_is_backed_now(self):
        for m in self.doc["memberships"]:
            if D.membership_status(self.doc, m, self.t) == "active":
                st_, until = D.chain_status(self.doc, m["under"], self.t)
                assert st_ in ("ok", "grace") and D.membership_errors(self.doc, m, at=self.t) == []

    @invariant()
    def a_revoke_leaves_nothing_below_it(self):
        for r in self.doc["admin_revocations"]:
            if r["mode"] != "revoke":
                continue
            below = {r["id"]} | {d["delegation_id"] for d in D._descendants(self.doc, r["id"])}
            for m in self.doc["memberships"]:
                if m["under"] in below:
                    assert D.membership_status(self.doc, m, self.t) != "active"


Deputies.TestCase.settings = settings(max_examples=40, stateful_step_count=25, deadline=None, database=None)
TestDeputies = Deputies.TestCase


def test_one_check_folds_each_membership_once_and_finds_the_same_errors(monkeypatch):
    """Found in a review (2026-10-23): a check folded the same memberships tens of thousands of times. Inside one memo scope
    each membership is folded once per moment, and the answer is the same as without it."""
    doc = demo()
    plain = D.check(doc)
    calls = []
    real = D._membership_status
    monkeypatch.setattr(D, "_membership_status", lambda d, m, at: calls.append((m["membership_id"], at)) or real(d, m, at))
    with D.memo():
        assert D.check(doc) == plain
    assert len(calls) == len(set(calls))                  # never the same membership at the same moment twice
    with D.memo():
        before = len(calls)
        D.membership_status(doc, doc["memberships"][0], NOW)
        D.membership_status(doc, doc["memberships"][0], NOW)
        assert len(calls) - before <= 1
