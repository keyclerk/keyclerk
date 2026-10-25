# SPDX-License-Identifier: EUPL-1.2
"""Decision 0017, step 1: the scaled separation-of-duties check gives exactly the answers of the direct form, on the
fixture, on generated organisations and when an SoD entitlement arrives through an included group; and it skips the
start times that cannot bring an SoD entitlement."""
import copy
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from keyclerk import delegation as D

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import bench_checks  # noqa: E402

FIXTURE = yaml.safe_load((ROOT / "tests" / "fixtures" / "records.yaml").read_text(encoding="utf-8"))


def moments(doc):
    return sorted({D._ts(m["start"]) for m in doc.get("memberships", [])} | {datetime(2026, 11, 1, tzinfo=timezone.utc)})


def with_conflict(doc, include: bool):
    """A real SoD conflict: Gina books payments (finance) and is added to payment-approvers, directly or through an
    include of the whole finance group (the path an include hides)."""
    d = copy.deepcopy(doc)
    template = next(m for m in d["memberships"] if m["membership_id"] == "M-example-0008")   # made by the root
    member = {"group": "finance"} if include else {"anchor": "idp:77dd-gina"}
    new = {k: v for k, v in copy.deepcopy(template).items() if k != "standby_from"}   # a plain, always-on membership
    d["memberships"].append({**new, "membership_id": "M-sod-test", "group": "payment-approvers", "member": member})
    return d


def with_suspension(doc):
    """Gina suspended from mid-October, never lifted: she drops out of every group from then."""
    d = with_conflict(doc, include=False)
    d["suspensions"] = [{"suspension_id": "S-test", "anchor": "idp:77dd-gina", "by": "idp:2b9e-owner",
                         "at": datetime(2026, 10, 15, tzinfo=timezone.utc), "reason": "test"}]
    return d


def with_agent(doc):
    """An agent acting for Gina, in finance and payment-approvers like her: it reaches only as far as she does."""
    d = with_conflict(doc, include=False)
    d["persons"].append({"person": "assistant-gina", "kind": "agent", "anchors": ["agent:assistant-gina"],
                         "owner": "idp:77dd-gina", "director": "idp:77dd-gina"})
    for m in [x for x in d["memberships"] if x["membership_id"] in ("M-example-0005", "M-sod-test")]:
        d["memberships"].append({**copy.deepcopy(m), "membership_id": m["membership_id"] + "-agent",
                                 "member": {"anchor": "agent:assistant-gina"}})
    return d


CASES = [("fixture", FIXTURE), ("generated 12", bench_checks.organisation(12)),
         ("direct conflict", with_conflict(FIXTURE, include=False)), ("conflict through an include", with_conflict(FIXTURE, include=True)),
         ("a suspension", with_suspension(FIXTURE)), ("an agent of the conflicted person", with_agent(FIXTURE))]


@pytest.fixture(params=["warn", "enforce"])
def persona(request, monkeypatch):
    """Both persona modes: under enforce the identity policy and the agent rule run inside the expansion."""
    monkeypatch.setattr(D, "persona_mode", lambda: request.param)
    return request.param


@pytest.mark.parametrize("name, doc", CASES)
def test_the_scaled_sod_check_answers_as_the_direct_form(name, doc):
    with D.memo():
        for t in moments(doc):
            assert D.sod_conflicts(doc, t) == D.sod_conflicts_reference(doc, t), (name, t)


@pytest.mark.parametrize("name, doc", CASES)
def test_the_timeline_finds_exactly_the_conflicts_of_checking_everyone_at_every_start(name, doc, persona):
    now = datetime.now(timezone.utc)
    with D.memo():
        full = {(c["anchor"], c["sod"], tuple(c["via"])) for t in D.sod_times(doc, now, every=True)
                for c in D.sod_conflicts_reference(doc, t)}
        timeline = {(c["anchor"], c["sod"], tuple(c["via"])) for c in D.sod_timeline(doc, now)}
    assert timeline == full, name


@pytest.mark.parametrize("name, doc", CASES)
def test_member_of_answers_as_expanding_the_group(name, doc, persona):
    """For every person, group and moment of the case: member_of equals membership of effective_members."""
    anchors = sorted({m["member"]["anchor"] for m in doc["memberships"] if "anchor" in m["member"]}
                     | {a for p in doc.get("persons", []) for a in p["anchors"]})
    groups = [g["group_id"] for g in doc["groups"]]
    with D.memo():
        for t in moments(doc)[::max(1, len(moments(doc)) // 12)] + [moments(doc)[-1]]:
            for g in groups:
                members = D.effective_members(doc, g, t)
                for a in anchors:
                    assert D.member_of(doc, a, g, t) == (a in members), (name, a, g, t)


def test_the_conflict_cases_really_conflict():
    for include in (False, True):
        with D.memo():
            errs = D.check(with_conflict(FIXTURE, include))
        assert any(e.startswith("SoD SOD-1: idp:77dd-gina") for e in errs), (include, [e for e in errs if "SoD" in e])


def test_starts_that_cannot_bring_an_sod_entitlement_are_skipped():
    doc = bench_checks.organisation(20)
    now = datetime.now(timezone.utc)
    assert len(D.sod_times(doc, now)) < len(D.sod_times(doc, now, every=True))


def test_the_check_stays_within_its_budget_at_a_thousand_people():
    """Decision 0017's budget, generous for a slower CI runner (measured 2026-10-24 on the workstation: 4.3 s; the
    baseline that morning was 136 s at 50 people)."""
    doc = bench_checks.organisation(1000)
    from keyclerk.reconcile import check_records
    t = time.perf_counter()
    errs = set(check_records(doc))
    assert time.perf_counter() - t < 30
    assert not [e for e in errs if "gen-" in e or "M-gen" in e]                 # the generated part stays valid


@pytest.mark.parametrize("name, doc", [("fixture", FIXTURE), ("generated 8", bench_checks.organisation(8)),
                                       ("direct conflict", with_conflict(FIXTURE, include=False))])
def test_the_indexes_inside_one_check_answer_as_the_scans(name, doc):
    """person_of and the reciprocity count use indexes built once per memo scope; outside it they scan. Same answers."""
    scanned = D.check(doc)
    with D.memo():
        indexed = D.check(doc)
    assert indexed == scanned, name
