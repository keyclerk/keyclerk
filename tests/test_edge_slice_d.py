# SPDX-License-Identifier: EUPL-1.2
"""Decision 0014c (slice D): carried visit leases, phoned unlock, the ended notice, key rotation, the silence alarm,
incident closing, unique SSH keys and evidence forks."""
import json
import time
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from keyclerk import relay as R

from test_edge_api import ANN, ANN_PUB, GINA, FINN, OFFICER_KEY, EDGE_KEY, EVA, INGRID, OWNER, W, call, ceiling, edge_server  # noqa: F401
from test_edges import SSH, cosigned, statement

UNLOCK = E.unlock_private(E.new_unlock_private())        # kc-unlock-v2: P-256 (in the TPM on a real edge)
UNLOCK_PUB = E.unlock_public(UNLOCK)


def _set_ceiling(base, serial=1):
    c = ceiling(serial)
    assert call(base, "POST", "/edges/plant-a/ceiling", {"ceiling": E.seal_ceiling(OFFICER_KEY, c)},
                cookie="eva", csrf="c-eva", signed=False)[0] == 200


def _visit_lease(desk):
    """ann gets a hardware SSH key and a visit lease on plant-a."""
    keys = [k for k in desk.store.load()["person_keys"] if k["anchor"] == ANN]
    end = desk.propose(W(OWNER), {"action": "end_edge_record", "id": keys[0]["key_id"], "reason": "replace with an SSH-bearing key"})
    assert end["outcome"] == "applied"
    r = desk.propose(W(ANN), {"action": "enrol_person_key", "public_key": R.b64e(ANN_PUB), "ssh_key": SSH, "user_verification": True})
    desk.approve(W(INGRID), r["change_id"])
    r = desk.propose(W(OWNER), {"action": "grant_visit_lease", "edge": "plant-a", "person": ANN, "ssh_key": SSH, "targets": ["plc-ssh"], "hours": 48})
    assert desk.approve(W(INGRID), r["change_id"])["outcome"] == "applied"
    return next(v["lease_id"] for v in desk.store.load()["edge_visit_leases"])


def test_a_carried_lease_is_issued_after_a_fresh_sign_in_and_cannot_be_replayed(edge_server):
    base, desk = edge_server
    _set_ceiling(base)
    lid = _visit_lease(desk)
    assert call(base, "POST", f"/me/visit-leases/{lid}/carried", cookie="ann-old", csrf="c-ann2", signed=False)[0] == 403
    code, sealed = call(base, "POST", f"/me/visit-leases/{lid}/carried", cookie="ann", csrf="c-ann", signed=False)
    assert code == 200
    pins = {"edge": "plant-a", "bundle_key": sealed["key"]}
    now = datetime.now(timezone.utc)
    errs, out = E.verify_carried(sealed, pins, {}, now)
    assert errs == [] and out["lease"]["ssh_key"] == SSH and out["lease"]["role"] == "operator"
    assert E.verify_carried(sealed, pins, out["state"], now)[0]                      # the same one again: refused
    assert E.verify_carried(sealed, {**pins, "edge": "plant-b"}, {}, now)[0]          # another edge: refused
    assert call(base, "POST", f"/me/visit-leases/{lid}/carried", cookie="gina", csrf="c-gina", signed=False)[0] == 404   # not gina's


def test_a_phoned_unlock_is_read_by_a_second_person_and_the_edge_computes_the_same_code(edge_server):
    base, desk = edge_server
    eid = "plant-u"
    ek = Ed25519PrivateKey.generate()
    st = statement(eid, EVA, OFFICER_KEY, edge_key=ek, unlock=UNLOCK_PUB)      # the officer and the edge sign the unlock key
    r = desk.propose(W(OWNER), {"action": "enrol_edge", "edge_id": eid, "enrolment_key": E.public_hex(ek), "officer": EVA,
                                "officer_key": E.public_hex(OFFICER_KEY), "profile": "assured",
                                "statement": cosigned(st, OFFICER_KEY, ek),
                                "unlock_key": UNLOCK_PUB, "unlock_approvers": [GINA, FINN],
                                "targets": [{"target": "plc-ssh", "role": "operator", "entitlement": "admin-console"}]})
    assert desk.approve(W(INGRID), r["change_id"])["outcome"] == "applied"
    body = {"person": ANN, "target": "plc-ssh", "key_fingerprint": "SHA256:abc", "nonce": "n-1", "minutes": 30}
    assert call(base, "POST", f"/edges/{eid}/unlock", body, cookie="ann", csrf="c-ann", signed=False)[0] == 403   # not an approver
    code, out = call(base, "POST", f"/edges/{eid}/unlock", body, cookie="gina", csrf="c-gina", signed=False)
    assert code == 200
    key = call(base, "GET", "/edge-key", signed=False)[1]                             # pinned on the edge at installation
    assert key["unlock_format"] == "kc-unlock-v2"
    node = E.key_id(E.public_hex(ek))
    edge_side = E.unlock_code(E.unlock_secret(UNLOCK, key["unlock_key"], UNLOCK_PUB, eid, node),
                              eid, node, ANN, "SHA256:abc", "plc-ssh", "n-1", 30)
    assert out["code"] == edge_side and len(edge_side) == 10 and out["node"] == node
    other_node = E.unlock_code(E.unlock_secret(UNLOCK, key["unlock_key"], UNLOCK_PUB, eid, "0" * 16),
                               eid, "0" * 16, ANN, "SHA256:abc", "plc-ssh", "n-1", 30)
    assert other_node != edge_side                                                   # bound to the node (two per edge in the HA profile)
    piped = call(base, "POST", f"/edges/{eid}/unlock", {**body, "key_fingerprint": "SHA256:a|b"}, cookie="gina",
                 csrf="c-gina", signed=False)
    assert piped[0] == 422                                                             # no field can shift into another
    self_unlock = call(base, "POST", f"/edges/{eid}/unlock", {**body, "person": GINA}, cookie="gina", csrf="c-gina", signed=False)
    assert self_unlock[0] == 422                                                       # never yourself
    for _ in range(2):
        call(base, "POST", f"/edges/{eid}/unlock", body, cookie="finn", csrf="c-finn", signed=False)
    assert call(base, "POST", f"/edges/{eid}/unlock", body, cookie="finn", csrf="c-finn", signed=False)[0] == 422   # 3 an hour
    assert any(i["kind"] == "phoned_unlock" for i in desk.edge_store.incidents(eid))


def test_an_ended_edge_is_told_so_signed_and_a_rotated_key_replaces_the_old_one(edge_server):
    base, desk = edge_server
    new = Ed25519PrivateKey.generate()
    enrolment = statement("plant-a", EVA, OFFICER_KEY, edge_key=new)               # an enrolment statement: wrong purpose
    r = desk.propose(W(OWNER), {"action": "rotate_edge", "edge_id": "plant-a", "enrolment_key": E.public_hex(new), "officer": EVA,
                                "officer_key": E.public_hex(OFFICER_KEY), "statement": cosigned(enrolment, OFFICER_KEY, new)})
    assert r["outcome"] == "refused" and any("purpose differ" in x for x in r["reasons"])
    st = statement("plant-a", EVA, OFFICER_KEY, edge_key=new, purpose="rotation")
    r = desk.propose(W(OWNER), {"action": "rotate_edge", "edge_id": "plant-a", "enrolment_key": E.public_hex(new), "officer": EVA,
                                "officer_key": E.public_hex(OFFICER_KEY), "statement": cosigned(st, OFFICER_KEY, new)})
    assert r["outcome"] == "pending" and desk.approve(W(INGRID), r["change_id"])["outcome"] == "applied"
    assert call(base, "GET", "/edge/bundle")[0] == 401                                 # the old key no longer signs for it
    h = E.sign_request(new, "plant-a", "GET", "/api/v1/edge/bundle", b"")
    assert call(base, "GET", "/edge/bundle", header=h)[0] == 200
    desk.propose(W(OWNER), {"action": "end_edge_record", "id": "plant-a", "reason": "decommissioned"})
    code, notice = call(base, "GET", "/edge/bundle", header=E.sign_request(new, "plant-a", "GET", "/api/v1/edge/bundle", b""))
    assert code == 410 and E.unseal(notice, notice["key"], E.ENDED_FORMAT)["reason"] == "decommissioned"
    pins = {"edge": "plant-a", "bundle_key": call(base, "GET", "/edge-key", signed=False)[1]["key"]}
    assert E.verify_ended(notice, pins, E.public_hex(new))[0] == []                 # this node's key: stop and wipe
    assert E.verify_ended(notice, pins, E.public_hex(EDGE_KEY))[0]                  # not the old key's


def test_a_silent_edge_raises_one_incident_and_incidents_close(edge_server):
    base, desk = edge_server
    _set_ceiling(base)
    call(base, "GET", "/edge/bundle")
    real = desk.clock
    desk.clock = lambda: real() + timedelta(hours=30)
    try:
        assert desk.edge_silence() == ["plant-a"] and desk.edge_silence() == []          # once
    finally:
        desk.clock = real
    inc = desk.edge_store.incidents("plant-a")[-1]
    assert inc["kind"] == "edge_silent"
    assert call(base, "POST", f"/edges/plant-a/incidents/{inc['incident_id']}/close", {"note": "site power cut"},
                cookie="finn", csrf="c-finn", signed=False)[0] == 403                    # not the officer
    assert call(base, "POST", f"/edges/plant-a/incidents/{inc['incident_id']}/close", {"note": "site power cut"},
                cookie="eva", csrf="c-eva", signed=False)[0] == 200


def test_an_ssh_key_belongs_to_one_person_and_a_broken_chain_is_an_incident(edge_server):
    base, desk = edge_server
    _visit_lease(desk)                                                     # ann's key carries the SSH key now
    r = desk.propose(W("idp:44aa-dirk"), {"action": "enrol_person_key", "public_key": R.b64e(R.person_key_from_prf(b"2" * 32)[1]),
                                          "ssh_key": SSH, "user_verification": True})
    assert any("another person" in x for x in r["reasons"])
    bad = {"seq": 5, "prev": "f" * 64, "sha256": "a" * 64, "size": 1, "session": "S", "at": "2026-10-23T10:00:00Z"}
    assert call(base, "POST", "/edge/evidence", {"entries": [bad]})[0] == 422
    assert desk.edge_store.incidents("plant-a")[-1]["kind"] == "evidence_fork"
