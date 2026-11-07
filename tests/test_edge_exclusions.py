# SPDX-License-Identifier: EUPL-1.2
"""Cross-edge exclusions (0.29): of the edges an exclusion names, one person holds access on one at a time. The desk
refuses an overlap it can see in the records; the bundle derivation, which the checking signer runs too, keeps exactly
one of two overlapping entries, so a bypassed desk still cannot put a person on both edges."""
import copy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from keyclerk import edge_grants as G
from keyclerk import edge_records as ER
from keyclerk import records

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BERT = "idp:91d0-bert"
NOW = datetime(2026, 11, 6, 12, tzinfo=timezone.utc)
HORIZONS = {"low": 24, "elevated": 8, "privileged": 4}


def edge(eid: str) -> dict:
    return {"edge_id": eid, "targets": [{"target": "share", "role": "reader", "entitlement": "share-read"}]}


def doc_with(*exclusions, edges=("site-north", "site-south")) -> dict:
    doc = copy.deepcopy(records.load(FIXTURES / "records.yaml"))
    doc["edges"] = [edge(e) for e in edges]
    doc["edge_exclusions"] = [{"exclusion_id": f"EX-{i}", "edges": list(x), "by": "idp:31ee-ingrid", "at": NOW,
                               "reason": "twin sites"} for i, x in enumerate(exclusions)]
    return doc


def carried(doc: dict, eid: str) -> set[str]:
    e = next(x for x in doc["edges"] if x["edge_id"] == eid)
    gone = G.excluded(doc, e, NOW, HORIZONS)
    return {lid for p, lid, *_ in G._holdings(doc, e, NOW, HORIZONS) if p == BERT and lid not in gone}


def test_without_an_exclusion_a_person_holds_both_edges():
    doc = doc_with()
    assert carried(doc, "site-north") and carried(doc, "site-south")


def test_with_an_exclusion_exactly_one_edge_carries_the_person():
    doc = doc_with(("site-north", "site-south"))
    north, south = carried(doc, "site-north"), carried(doc, "site-south")
    assert bool(north) != bool(south)
    assert north                                   # same start: the edge listed first keeps it


def test_both_edges_compute_the_same_answer_whatever_the_order_of_records():
    doc = doc_with(("site-south", "site-north"))
    assert carried(doc, "site-south") and not carried(doc, "site-north")
    doc["edges"].reverse()
    assert carried(doc, "site-south") and not carried(doc, "site-north")


def test_an_ended_exclusion_no_longer_holds():
    doc = doc_with(("site-north", "site-south"))
    doc["admin_revocations"] = list(doc.get("admin_revocations", [])) + [
        {"id": "EX-0", "at": NOW, "by": "idp:31ee-ingrid", "mode": "retire", "reason": "the site closed"}]
    assert carried(doc, "site-north") and carried(doc, "site-south")


def test_a_third_edge_outside_the_exclusion_is_untouched():
    doc = doc_with(("site-north", "site-south"), edges=("site-north", "site-south", "lab"))
    assert carried(doc, "lab")


def test_the_records_check_names_the_overlap_the_desk_refuses():
    errs = ER.exclusion_errors(doc_with(("site-north", "site-south")))
    assert any(e.startswith("EX-0: M-example-0001 ") for e in errs), errs


def test_an_exclusion_naming_an_unknown_edge_is_refused():
    assert any("no such edge plant-x" in e for e in ER.exclusion_errors(doc_with(("site-north", "plant-x"))))


def test_windows_that_do_not_overlap_are_fine():
    doc = doc_with(("site-north", "site-south"))
    doc["memberships"] = []                        # only the two visit leases below reach these edges
    doc["edge_visit_leases"] = [
        {"lease_id": "VL-1", "edge": "site-north", "person": BERT, "ssh_key": "k", "targets": ["share"],
         "from": "2026-11-06T08:00:00Z", "until": "2026-11-06T16:00:00Z", "by": "idp:2b9e-owner", "reason": "r"},
        {"lease_id": "VL-2", "edge": "site-south", "person": BERT, "ssh_key": "k", "targets": ["share"],
         "from": "2026-11-06T16:00:00Z", "until": "2026-11-07T00:00:00Z", "by": "idp:2b9e-owner", "reason": "r"}]
    assert ER.exclusion_errors(doc) == []
    doc["edge_visit_leases"][1]["from"] = "2026-11-06T15:00:00Z"
    assert any("VL-1 on site-north and VL-2 on site-south" in e for e in ER.exclusion_errors(doc))


def test_the_desk_action_is_the_root_or_the_security_officers(tmp_path):
    from keyclerk.desk import Refusal
    from test_edges import INGRID, enrol, edge_desk
    from test_visits import Clock
    desk = edge_desk(tmp_path, clock=Clock(NOW))
    desk.approve({"anchor": INGRID, "roles": []}, enrol(desk)["change_id"])
    with pytest.raises(Refusal, match="no edge plant-z"):
        desk.propose({"anchor": INGRID, "roles": []}, {"action": "exclude_edges", "edges": ["plant-a", "plant-z"],
                                                       "reason": "twin"})
    with pytest.raises(Refusal, match="root or the security officer"):
        desk.propose({"anchor": BERT, "roles": []}, {"action": "exclude_edges", "edges": ["plant-a", "plant-b"],
                                                     "reason": "twin"})
    with pytest.raises(Refusal, match="two to twenty"):
        desk.propose({"anchor": INGRID, "roles": []}, {"action": "exclude_edges", "edges": ["plant-a", "plant-a"],
                                                       "reason": "twin"})


def test_one_membership_whose_group_carries_both_edges_targets_is_named_as_such():
    errs = ER.exclusion_errors(doc_with(("site-north", "site-south")))
    assert any("gives one person both site-north and site-south" in e for e in errs), errs


def test_an_exclusion_error_is_in_the_reach_of_any_change_that_can_cause_it():
    """0.29 review X1: an overlap the records check names belongs to the subject "exclusions", which every change to
    memberships, visit leases, edges, revocations or groups reaches, so the signer's scoped check never drops it."""
    from keyclerk import scope
    doc = doc_with(("site-north", "site-south"))
    err = next(e for e in ER.exclusion_errors(doc) if e.startswith("EX-0: "))
    assert scope.subject_of(err, doc) == "exclusions"
    m = doc["memberships"][0]
    got = scope.reach(doc, doc, [{"op": "put", "kind": "memberships", "key": m["membership_id"], "record": m}])
    assert not isinstance(got, scope.Full) and scope.covered("exclusions", got)


def test_an_exclusion_can_be_ended():
    """0.29 review X2: ending an exclusion names its id, which the records know."""
    from keyclerk import delegation as D
    doc = doc_with(("site-north", "site-south"))
    doc["admin_revocations"] = list(doc.get("admin_revocations", [])) + [
        {"id": "EX-0", "at": NOW, "by": "idp:31ee-ingrid", "mode": "retire", "reason": "the site closed"}]
    assert not [e for e in D.check(doc) if "unknown id EX-0" in e]


def test_overlaps_that_ended_before_the_exclusion_are_history():
    """0.29 review X3: an exclusion governs from its own time; two entries that overlapped last year do not refuse it."""
    from datetime import timedelta
    doc = doc_with(("site-north", "site-south"))
    later = max(ER._end_of(doc, m["membership_id"], ER._ts(m["end"])) for m in doc["memberships"]) + timedelta(days=1)
    doc["edge_exclusions"][0]["at"] = later
    assert not [e for e in ER.exclusion_errors(doc) if e.startswith("EX-0: ")]


def test_a_derived_lease_has_a_stable_start_through_its_inclusion(monkeypatch):
    """0.29 review X4: a lease through an included group starts, for the tie-break, at the later of the inclusion's
    start and the person's start in the included group, the same on every edge, instead of always losing."""
    from datetime import timedelta
    doc = doc_with()
    t1, t2 = NOW - timedelta(days=30), NOW - timedelta(days=10)
    end = NOW + timedelta(days=30)
    doc["memberships"] = [
        {"membership_id": "M-in", "group": "G-inner", "member": {"anchor": BERT}, "by": "x", "under": "x",
         "start": t1, "end": end},
        {"membership_id": "M-inc", "group": "G-outer", "member": {"group": "G-inner"}, "by": "x", "under": "x",
         "start": t2, "end": end}]
    from keyclerk import delegation as D
    monkeypatch.setattr(D, "membership_status", lambda doc, m, at: "active")
    assert G._since(doc, "G-outer", BERT, NOW) == t2
    assert G._since(doc, "G-inner", BERT, NOW) == t1
    assert G._since(doc, "G-outer", "idp:nobody", NOW) is None


def test_a_backdated_visit_lease_is_refused_at_the_signer():
    """0.29 review X4: a desk cannot put a visit lease into the log that starts in the past."""
    from datetime import timedelta

    from keyclerk import edge as E
    from keyclerk.signer import Signer, SignerRefused

    class St:
        def get(self, kind, key):
            return None
    rec = {"lease_id": "VL-1", "from": E._iso(datetime.now(timezone.utc) - timedelta(days=2))}
    with pytest.raises(SignerRefused, match="starts in the past"):
        Signer._no_backdated_visits([{"op": "put", "kind": "edge_visit_leases", "key": "VL-1", "record": rec}], St())
    rec["from"] = E._iso(datetime.now(timezone.utc))
    Signer._no_backdated_visits([{"op": "put", "kind": "edge_visit_leases", "key": "VL-1", "record": rec}], St())
