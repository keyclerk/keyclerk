# SPDX-License-Identifier: EUPL-1.2
"""Places and situation levels: nested physical places with outposts, org units
over many places, and levels that narrow from any valid source but widen only from people, confirmed by a second."""
import copy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
from keyclerk import delegation as D  # noqa: E402
from keyclerk import places as PL  # noqa: E402
from keyclerk import records  # noqa: E402
from keyclerk import situation as S  # noqa: E402

DEMO = FIXTURES / "records.yaml"
INGRID, OWNER, BERT = "idp:31ee-ingrid", "idp:2b9e-owner", "idp:91d0-bert"


def utc(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


def demo() -> dict:
    return copy.deepcopy(records.load(DEMO))


def ann(doc, sid, level, at, by=INGRID, scope=None, **kw):
    doc["situations"].append({"situation_id": sid, "level": level, "scope": scope or {"kind": "tenant"},
                              "source": kw.pop("source", "officer"), "by": by, "at": at, **kw})


# --- places ------------------------------------------------------------------------------------------------------

def test_the_demo_places_are_clean_and_an_outpost_follows_the_site_that_runs_it():
    doc = demo()
    assert PL.check(doc) == []
    assert PL.scope_chain(doc, "place:herent-mast") == ["place:herent-mast", "place:vlaams-brabant", "place:heverlee"]
    assert PL.resolve(doc, "example-host-1") == "place:heverlee"
    assert PL.places_of_org(doc, "site-crews") >= {"place:heverlee/depot", "place:wilsele", "place:wilsele/yard"}
    assert PL.orgs_at(doc, "place:heverlee/main/0/reception") == {"office"}
    assert PL.shared(doc, "place:herent-hub")


def test_place_rules_refuse_impossible_shapes():
    doc = demo()
    doc["places"] += [{"place_id": "x:room", "kind": "room", "within": None},
                      {"place_id": "x:site", "kind": "site", "within": "place:heverlee/main"},
                      {"place_id": "x:mast", "kind": "outpost", "within": "place:vlaams-brabant", "belongs_to": "place:heverlee/main"},
                      {"place_id": "x:inner", "kind": "outpost", "within": "place:heverlee", "belongs_to": "place:heverlee"}]
    errs = PL.check(doc)
    assert any("x:site: a site cannot be within a building" in e for e in errs)
    assert any("x:mast: belongs to place:heverlee/main, which is not a site" in e for e in errs)
    assert any("x:inner: an outpost is never inside the site it belongs to" in e for e in errs)


# --- levels ------------------------------------------------------------------------------------------------------

def test_the_demo_history():
    doc = demo()
    assert S.check(doc) == []
    assert S.levels(doc, None, utc("2026-10-18T12:00"))["restriction"] == "elevated"         # a feed
    assert S.levels(doc, None, utc("2026-10-18T12:00"))["activation"] == "normal"            # a feed never activates
    assert S.levels(doc, None, utc("2026-10-20T12:00"))["activation"] == "high"              # confirmed by the rota
    now = utc("2026-10-22T12:00")
    assert S.levels(doc, None, now)["restriction"] == "elevated"                             # lowered by two people
    assert S.levels(doc, "place:wilsele/yard", now)["restriction"] == "high"                 # the site's own level
    assert S.levels(doc, "place:heverlee/main", now)["restriction"] == "elevated"            # not Wilsele's


def test_a_feed_raises_one_step_at_most_never_past_high_and_a_reused_nonce_counts_for_nothing():
    doc = demo()
    doc["situations"] = [s for s in doc["situations"] if s["source"].startswith("feed:")]   # elevated, nonce rt-...-1
    feed = {"by": "feed:regional-threat", "source": "feed:regional-threat"}
    ann(doc, "F2", "severe", "2026-10-19T09:00:00Z", nonce="rt-2", issued_at="2026-10-19T08:59:00Z", **feed)
    assert S.levels(doc, None, utc("2026-10-19T10:00"))["restriction"] == "elevated"         # one step above people
    ann(doc, "P1", "high", "2026-10-19T10:00:00Z", approved_by=[OWNER])
    ann(doc, "F3", "severe", "2026-10-19T17:00:00Z", nonce="rt-3", issued_at="2026-10-19T16:59:00Z", **feed)
    assert S.levels(doc, None, utc("2026-10-19T18:00"))["restriction"] == "high"             # never past high
    ann(doc, "P2", "normal", "2026-10-20T10:00:00Z", approved_by=[OWNER])
    ann(doc, "F4", "elevated", "2026-10-20T18:00:00Z", nonce="rt-3", issued_at="2026-10-20T17:59:00Z", **feed)
    assert S.levels(doc, None, utc("2026-10-20T19:00"))["restriction"] == "normal"           # replayed nonce
    ann(doc, "F5", "elevated", "2026-10-21T01:00:00Z", nonce="rt-5", issued_at="2026-10-20T00:00:00Z", **feed)
    assert S.levels(doc, None, utc("2026-10-21T02:00"))["restriction"] == "normal"           # stale record
    ann(doc, "F6", "elevated", "2026-10-21T03:00:00Z", nonce="rt-6", issued_at="2026-10-21T02:59:00Z", **feed)
    assert S.levels(doc, None, utc("2026-10-21T04:00"))["restriction"] == "elevated"


def test_an_unconfirmed_raise_activates_only_until_its_confirmation_deadline():
    doc = demo()
    doc["situations"] = []
    ann(doc, "A1", "high", "2026-10-19T07:00:00Z")
    assert S.levels(doc, None, utc("2026-10-19T12:00"))["activation"] == "high"
    assert S.levels(doc, None, utc("2026-10-19T20:00"))["activation"] == "normal"            # no second person
    assert S.levels(doc, None, utc("2026-10-19T20:00"))["restriction"] == "high"             # restrictions stay


def test_lowering_needs_a_second_person_who_did_not_raise_and_waits_for_the_dwell():
    doc = demo()
    doc["situations"] = []
    ann(doc, "A1", "high", "2026-10-19T07:00:00Z")
    ann(doc, "A2", "normal", "2026-10-19T08:00:00Z", approved_by=[OWNER])                   # within the dwell
    ann(doc, "A3", "normal", "2026-10-19T15:00:00Z")                                        # one person
    ann(doc, "A4", "normal", "2026-10-19T16:00:00Z", by=BERT, approved_by=[OWNER])          # the rota never lowers
    assert S.levels(doc, None, utc("2026-10-19T17:00"))["restriction"] == "high"
    ann(doc, "A5", "normal", "2026-10-19T18:00:00Z", approved_by=[OWNER])
    assert S.levels(doc, None, utc("2026-10-19T19:00"))["restriction"] == "normal"


def test_an_exercise_never_changes_production_and_a_dry_run_shows_its_effect():
    doc = demo()
    at = utc("2026-10-23T12:00")
    assert S.levels(doc, None, at)["restriction"] == "elevated"
    run = S.dry_run(doc, "S-example-0006")
    assert run["levels"]["restriction"] == "severe" and run["leases_dormant"] == ["L-example-0001"]
    assert run["standby_on"] == ["M-example-0008"]


def test_only_people_with_standing_announce_and_a_shared_place_by_its_steward():
    doc = demo()
    ann(doc, "X1", "high", "2026-10-22T09:00:00Z", by="idp:77dd-gina")
    ann(doc, "X2", "high", "2026-10-22T09:00:00Z", scope={"kind": "place", "id": "place:herent-hub"})
    errs = S.check(doc)
    assert any("X1: announced by someone who may not" in e for e in errs)
    assert any("X2: a shared place's level is announced by its steward" in e for e in errs)


# --- what levels do ----------------------------------------------------------------------------------------------

def test_standby_turns_on_with_the_activation_level_and_off_when_it_falls():
    doc = demo()
    m = next(x for x in doc["memberships"] if x["membership_id"] == "M-example-0008")
    assert D.membership_status(doc, m, utc("2026-10-20T12:00")) == "active"
    assert D.membership_status(doc, m, utc("2026-10-22T12:00")) == "standby"
    assert "idp:77dd-gina" not in D.effective_members(doc, "crisis-team", utc("2026-10-22T12:00"))


def test_surge_grants_live_with_the_level_and_go_to_review_after_it():
    doc = demo()
    g = doc["surge_grants"][0]
    assert S.surge_status(doc, g, utc("2026-10-20T12:00")) == "active"
    assert "idp:bb11-kai" in D.effective_members(doc, "site-heverlee", utc("2026-10-20T12:00"))
    assert S.surge_status(doc, g, utc("2026-10-22T12:00")) == "ended"
    assert S.reviews_due(doc, utc("2026-10-22T12:00"))[0]["item"] == "SG-example-0001"


def test_surge_limits_cap_coordinator_privileged_and_cumulative_days():
    doc = demo()
    for i in range(2, 8):
        doc["surge_grants"].append({"surge_id": f"SG-x{i}", "package_id": "SP-example-0001", "anchor": f"idp:s{i}",
                                    "by": BERT, "at": "2026-10-19T11:00:00Z", "end": "2026-10-20T11:00:00Z"})
    assert any("above the package cap" in e for e in S.surge_errors(doc, doc["surge_grants"][-1]))
    bad = {**doc["surge_grants"][0], "surge_id": "SG-y", "by": INGRID}
    assert any("never the officer" in e for e in S.surge_errors(doc, bad))
    doc["surge_packages"][0]["groups"].append("admins")
    assert any("privileged" in e for e in S.package_errors(doc, doc["surge_packages"][0]))
    doc = demo()
    for i in range(8):   # renewals of one person across raised episodes add up
        t0 = utc("2026-10-19T10:00") + timedelta(hours=48 * i)
        doc["surge_grants"].append({"surge_id": f"SG-k{i}", "package_id": "SP-example-0001", "anchor": "idp:bb11-kai",
                                    "by": BERT, "at": t0.isoformat(), "end": (t0 + timedelta(hours=48)).isoformat()})
    assert any("surge days" in e for e in S.surge_errors(doc, doc["surge_grants"][-1]))


def test_a_raised_level_suspends_visitor_categories_raises_floors_and_shrinks_the_deputy_cap():
    doc = demo()
    ann(doc, "V1", "severe", "2026-10-22T13:00:00Z", approved_by=[OWNER])
    at = utc("2026-10-22T14:00")
    assert S.dormant_leases(doc, at)["L-example-0001"].startswith("contractor suspended at severe")
    assert S.floor_raise("external", "severe") == 2 and S.floor_raise("tenant", "severe") == 1
    assert D.opa_data(doc, at)["rules"]["widenings_per_deputy_per_day"] == 0


def test_a_place_limited_delegation_covers_only_groups_at_that_place():
    doc = demo()
    d = {**doc["delegations"][1], "delegation_id": "D-place", "delegate": "idp:44aa-dirk", "group": "sites",
         "powers": ["members"], "depth_left": 0, "by": BERT, "parent": "D-example-0002", "place": "place:wilsele",
         "start": "2026-10-22T00:00:00Z", "end": "2026-12-31T00:00:00Z", "max_membership_days": 30}
    doc["delegations"].append(d)
    at = utc("2026-10-22T12:00")
    assert D.authority(doc, "idp:44aa-dirk", "site-wilsele", "members", at) == "D-place"
    assert D.authority(doc, "idp:44aa-dirk", "site-heverlee", "members", at) is None
