# SPDX-License-Identifier: EUPL-1.2
"""Edge protocol 1.4 (issue 31, decisions 0019, 0020 and 0030 point 7): the bundle carries the records head it was cut
from and the edge echoes it (edges as weak witnesses), the report confirms removals per lease (the leaver proof) and
declares the bastion's capabilities, and an evidence entry names the lease its session ran under. Each is optional:
an edge without them keeps working."""
from datetime import datetime, timedelta, timezone

import pytest

from keyclerk import edge as E
from keyclerk import edge_store as ES
from keyclerk.desk import MAX_REMOVALS
from test_edge_api import ANN, _bundle_with_ceiling, call, edge_server  # noqa: F401


def _kinds(desk):
    return [i["kind"] for i in desk.edge_store.incidents("plant-a")]


def _report(base, **extra):
    return call(base, "POST", "/edge/report", {"applied_serial": 1, "attestation": {"profile": "basic"}, "drift": [],
                                               **extra})


def test_the_bundle_carries_the_records_head_and_an_echo_of_it_is_no_incident(edge_server):
    base, desk = edge_server
    body = _bundle_with_ceiling(base)
    assert body["records_head"] == desk.store.records_head() and body["records_head"]["revision"] >= 1
    code, out = _report(base, records_head=body["records_head"])
    assert code == 200, out
    assert desk.edge_store.state("plant-a")["report"]["records_head"] == body["records_head"]
    assert not {"records_head_ahead", "records_head_unknown"} & set(_kinds(desk))


def test_an_edge_that_applied_newer_records_than_the_desk_holds_is_an_incident_once(edge_server):
    base, desk = edge_server
    head = _bundle_with_ceiling(base)["records_head"]
    ahead = {**head, "revision": head["revision"] + 5}                   # the desk was restored from an older backup
    assert _report(base, records_head=ahead)[0] == 200
    assert _report(base, records_head=ahead)[0] == 200
    assert _kinds(desk).count("records_head_ahead") == 1
    other = {**head, "head": "ab" * 32}                                  # the same revision, another records hash
    assert _report(base, records_head=other)[0] == 200
    assert "records_head_unknown" in _kinds(desk)


def test_on_the_change_log_a_head_the_log_does_not_hold_is_another_history(edge_server):
    base, desk = edge_server
    hashes = {3: "cd" * 32}
    desk.store.records_head = lambda: {"revision": 9, "size": 5, "head": "ef" * 32}   # a desk on the log, stubbed
    desk.store.head_at = lambda size: hashes.get(size)
    desk._echoed_head("plant-a", {"revision": 2, "size": 3, "head": "cd" * 32})       # the log holds it
    assert "records_head_unknown" not in _kinds(desk)
    desk._echoed_head("plant-a", {"revision": 2, "size": 3, "head": "00" * 32})
    assert "records_head_unknown" in _kinds(desk)


@pytest.mark.parametrize("bad", [None, {"revision": 1}, {"revision": -1, "head": "ab" * 32},
                                 {"revision": 1, "head": "AB" * 32}, {"revision": 1, "head": "ab" * 32, "size": 0},
                                 {"revision": 1, "head": "ab" * 32, "seq": 1}])
def test_a_malformed_records_head_is_refused_in_reports_and_bundles(edge_server, bad):
    base, _ = edge_server
    assert _report(base, records_head=bad)[0] == 400
    assert E.records_head_errors(bad)


def test_a_verifier_refuses_a_bundle_whose_records_head_is_malformed_and_reads_absent_as_absent():
    from tests.test_ceiling_hours import _bundle
    errs, applied = _bundle("2026-10-23T19:00:00Z")
    assert not errs and applied["records_head"] is None                   # absent: an older desk's bundle
    bk = E.Ed25519PrivateKey.from_private_bytes(b"b" * 32)
    pol = {"modules": {}, "release": None, "entrypoints": []}
    pins = {"edge": "edge-a", "bundle_key": E.public_hex(bk), "officer_key": E.public_hex(bk), "release_key": None}
    now = datetime(2026, 10, 23, 13, 0, tzinfo=timezone.utc)
    t0 = now - timedelta(hours=1)
    good = E.build_bundle("edge-a", 7, t0, {"low": 12}, [], [], [], None, pol, bk,
                          records_head={"revision": 4, "head": "ab" * 32})
    errs, applied = E.verify_bundle(good, pins, {"serial": 6}, now)
    assert not errs and applied["records_head"] == {"revision": 4, "head": "ab" * 32}
    bad = E.build_bundle("edge-a", 7, t0, {"low": 12}, [], [], [], None, pol, bk, records_head={"revision": "4"})
    assert any("records_head" in e for e in E.verify_bundle(bad, pins, {"serial": 6}, now)[0])
    null = E.seal(bk, {**E.unseal(good, E.public_hex(bk), E.BUNDLE_FORMAT), "records_head": None}, E.BUNDLE_FORMAT)
    assert any("records_head" in e for e in E.verify_bundle(null, pins, {"serial": 6}, now)[0])


def test_removals_are_kept_once_per_lease_and_refused_when_malformed(edge_server):
    base, desk = edge_server
    lease = next(x for x in _bundle_with_ceiling(base)["leases"] if x["person"] == ANN)
    one = {"lease_id": lease["lease_id"], "system": "bastion-a", "at": "2026-11-04T09:30:00+01:00"}
    assert _report(base, removals=[one])[0] == 200
    assert _report(base, removals=[{**one, "at": "2026-11-04T10:00:00Z"}])[0] == 200     # a repeat: no change
    kept = desk.edge_store.removals("plant-a")
    assert [(r["lease_id"], r["at"]) for r in kept] == [(lease["lease_id"], "2026-11-04T08:30:00Z")]
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for bad in ([{**one, "at": future}], [{**one, "at": "2026-11-04T09:30:00"}], [{"lease_id": "L-1"}], "L-1",
                [one] * (MAX_REMOVALS + 1)):
        assert _report(base, removals=bad)[0] == 400, bad



def test_the_bastion_declares_what_it_enforces_and_a_change_is_an_incident(edge_server):
    base, desk = edge_server
    decl = {"product": "warpgate", "version": "0.30.1", "capabilities": ["expires_grants", "records_sessions",
                                                                         "a_future_token"], "adapter": ["reads_hardening"]}
    assert _report(base, bastion=decl)[0] == 200
    seen = desk.edge_store.state("plant-a")["report"]["bastion"]
    assert seen == {"product": "warpgate", "version": "0.30.1", "capabilities": ["expires_grants", "records_sessions"],
                    "adapter": ["reads_hardening"], "unknown": ["a_future_token"]}   # kept apart, never refused
    assert _report(base, bastion={**decl, "capabilities": ["records_sessions"]})[0] == 200
    assert "bastion_changed" in _kinds(desk)
    assert _report(base)[0] == 200
    assert "bastion" not in desk.edge_store.state("plant-a")["report"]                # absent: unknown, not "none"
    for bad in ({"product": "warpgate"}, {**decl, "capabilities": "records_sessions"}, {**decl, "extra": 1},
                {**decl, "capabilities": [1]}):
        assert _report(base, bastion=bad)[0] == 400, bad


def test_an_evidence_entry_may_name_the_lease_its_session_ran_under(edge_server):
    base, desk = edge_server
    first = {"seq": 1, "prev": "0" * 64, "sha256": "ab" * 32, "size": 10, "session": "s-1", "at": "2026-11-04T09:00:00Z",
             "lease_id": "L-example-0001"}
    second = {"seq": 2, "prev": E.sha256(E.canonical(first)), "sha256": "cd" * 32, "size": 12, "session": "s-2",
              "at": "2026-11-04T09:05:00Z"}                               # without one, as before 1.4
    code, out = call(base, "POST", "/edge/evidence", {"entries": [first, second]})
    assert code == 200, out
    assert desk.edge_store.evidence_head("plant-a")[0] == 2
    bad = {**second, "seq": 3, "prev": E.sha256(E.canonical(second)), "lease_id": "not a lease id!"}
    assert call(base, "POST", "/edge/evidence", {"entries": [bad]})[0] == 400


def test_incident_kinds_an_edge_sends_are_unchanged():
    assert "records_head_ahead" not in ES.INCIDENT_KINDS                  # raised by the desk, never sent by an edge


def test_a_standing_drift_is_one_incident_and_the_cap_never_fails_a_report(edge_server):
    """Found by the interim soak: every report carrying the same drift raised an incident, and past the edge's cap of
    60 an hour the cap's refusal answered the report 500, so the edge resent it for ever (the report was stored)."""
    base, desk = edge_server
    _bundle_with_ceiling(base)
    for _ in range(70):                                   # an hour of reports with the same drift
        assert _report(base, drift=["lease L-1 names no username: not applied"])[0] == 200
    assert _kinds(desk).count("drift") == 1
    for i in range(70):                                   # a drift that changes every time: past the cap, still 200
        code, out = _report(base, drift=[f"lease L-{i} names no username: not applied"])
        assert code == 200, out
    assert _kinds(desk).count("drift") == ES.EdgeStore.INCIDENTS_PER_HOUR
