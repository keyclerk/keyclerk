# SPDX-License-Identifier: EUPL-1.2
"""Decision 0014 through the desk: an edge enrolled by the root with the security officer's key; a person key registered
by the person with a second key; a visit lease with a second key; the officer never a core administrator."""
from datetime import datetime, timezone

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import edge as E
from keyclerk import relay as R
from keyclerk.desk import Refusal
from keyclerk.desk import Desk, Store

from test_visits import FIXTURES, Clock

OWNER, INGRID, EVA, FINN, ANN = "idp:2b9e-owner", "idp:31ee-ingrid", "idp:55bb-eva", "idp:66cc-finn", "idp:7c1f-ann"
W = lambda a: {"anchor": a, "roles": []}   # noqa: E731
EDGE_KEY, OFFICER_KEY = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
_, PUB = R.person_key_from_prf(b"\x11" * 32)
SSH = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBk4bU2mPbJ6n0dO0eWq5d0q8v0k9s7rT1c2x3y4z5a6 finn@hardware-key"


@pytest.fixture
def desk(tmp_path):
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    d = Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"),
             clock=Clock(datetime(2026, 10, 24, 8, 0, tzinfo=timezone.utc)))
    return d


def cosigned(st: dict, *keys) -> dict:
    """A statement signed over the same bytes by each key, in turn (amendment 0014d)."""
    out = st
    for k in keys:
        out = E.cosign(k, out)
    return out


def statement(edge_id, officer, officer_key, edge_key=None, unlock=None, tpm=None, purpose="enrolment"):
    return E.officer_statement(edge_id, officer, E.public_hex(officer_key),
                               [E.node(E.public_hex(edge_key or EDGE_KEY), unlock, tpm)], purpose)


def enrol(desk, officer=EVA, edge_id="plant-a", officer_key=OFFICER_KEY, sign_with=None):
    st = statement(edge_id, officer, officer_key)
    return desk.propose(W(OWNER), {"action": "enrol_edge", "edge_id": edge_id, "enrolment_key": E.public_hex(EDGE_KEY),
                                   "officer": officer, "officer_key": E.public_hex(officer_key), "profile": "assured",
                                   "statement": cosigned(st, sign_with or officer_key, EDGE_KEY),
                                   "custodians": [FINN, "idp:77dd-gina"],
                                   "targets": [{"target": "plc-ssh", "role": "operator", "entitlement": "admin-console", "max_session_hours": 2}]})


def test_an_edge_waits_for_the_security_officers_key_and_then_is_enrolled(desk):
    r = enrol(desk)
    assert r["outcome"] == "pending" and any("security officer's key" in x for x in r["reasons"])
    done = desk.approve(W(INGRID), r["change_id"])
    assert done["outcome"] == "applied"
    assert [e["edge_id"] for e in desk.store.load()["edges"]] == ["plant-a"]


def test_a_core_administrator_is_never_an_edges_officer(desk):
    for officer in (OWNER, INGRID):                       # the root, the security officer
        r = enrol(desk, officer, "edge-" + officer[-4:])
        assert any("never a core administrator" in x for x in r["reasons"]), officer


def test_the_root_cannot_choose_the_officers_key(desk):
    """The officer proves the key by signing the enrolment statement with it."""
    rooted = Ed25519PrivateKey.generate()
    r = enrol(desk, officer_key=rooted, sign_with=OFFICER_KEY)      # the root names a key the officer did not sign with
    assert r["outcome"] == "refused" and any("officer signs the statement with their own key" in x for x in r["reasons"])


def test_a_statement_the_officer_signed_for_other_values_is_refused(desk):
    """Amendment 0014d: the signed bytes must say what the record holds (here another target edge id)."""
    st = statement("plant-z", EVA, OFFICER_KEY)
    r = desk.propose(W(OWNER), {"action": "enrol_edge", "edge_id": "plant-a", "enrolment_key": E.public_hex(EDGE_KEY),
                                "officer": EVA, "officer_key": E.public_hex(OFFICER_KEY), "profile": "assured",
                                "statement": cosigned(st, OFFICER_KEY, EDGE_KEY),
                                "targets": [{"target": "plc-ssh", "role": "operator", "entitlement": "admin-console"}]})
    assert r["outcome"] == "refused" and any("not this record's (edge differ)" in x for x in r["reasons"])


def test_a_statement_without_the_edges_signature_is_refused(desk):
    st = statement("plant-a", EVA, OFFICER_KEY)
    r = desk.propose(W(OWNER), {"action": "enrol_edge", "edge_id": "plant-a", "enrolment_key": E.public_hex(EDGE_KEY),
                                "officer": EVA, "officer_key": E.public_hex(OFFICER_KEY), "profile": "assured",
                                "statement": {**cosigned(st, OFFICER_KEY), "signatures": cosigned(st, OFFICER_KEY)["signatures"] * 2},
                                "targets": [{"target": "plc-ssh", "role": "operator", "entitlement": "admin-console"}]})
    assert r["outcome"] == "refused" and any("the edge signs the statement" in x for x in r["reasons"])


def test_an_ended_edge_id_is_never_enrolled_again(desk):
    """The desk refuses it, and so do the records checks, whoever wrote the records."""
    from keyclerk import edge_records
    r = enrol(desk)
    desk.approve(W(INGRID), r["change_id"])
    end = desk.propose(W(OWNER), {"action": "end_edge_record", "id": "plant-a", "reason": "decommissioned"})
    if end["outcome"] == "pending":
        end = desk.approve(W(INGRID), end["change_id"])
    assert end["outcome"] == "applied"
    from keyclerk.desk import Refusal
    with pytest.raises(Refusal, match="enrolled already"):
        enrol(desk)
    doc = desk.store.load()
    old = doc["edges"][0]
    later = {**old, "at": datetime(2026, 10, 25, 8, 0, tzinfo=timezone.utc)}
    forged = {**doc, "edges": [later]}                      # the old record removed, the id enrolled again
    assert any("never used again: enrol the machine under a new id" in x for x in edge_records.check(forged))


def test_only_the_root_enrols_an_edge(desk):
    st = statement("plant-b", EVA, OFFICER_KEY)
    r = desk.propose(W(ANN), {"action": "enrol_edge", "edge_id": "plant-b", "enrolment_key": E.public_hex(EDGE_KEY),
                              "officer": EVA, "officer_key": E.public_hex(OFFICER_KEY), "profile": "basic",
                              "statement": cosigned(st, OFFICER_KEY, EDGE_KEY),
                              "targets": [{"target": "plc-ssh", "role": "operator", "entitlement": "admin-console"}]})
    assert r["outcome"] == "refused" and any("enrolled by the root" in x for x in r["reasons"])


def test_a_person_key_is_my_own_and_waits_for_a_second_key(desk):
    r = desk.propose(W(FINN), {"action": "enrol_person_key", "public_key": R.b64e(PUB), "ssh_key": SSH,
                               "user_verification": True, "attestation": "packed"})
    assert r["outcome"] == "pending" and any("second key" in x for x in r["reasons"])
    assert desk.approve(W(INGRID), r["change_id"])["outcome"] == "applied"
    again = desk.propose(W(FINN), {"action": "enrol_person_key", "public_key": R.b64e(R.person_key_from_prf(b"\x12" * 32)[1]),
                                   "user_verification": True})
    assert any("one key per person" in x for x in again["reasons"])
    with pytest.raises(Refusal):
        desk.propose(W(FINN), {"action": "enrol_person_key", "public_key": "not-a-key", "user_verification": True})


def test_a_visit_lease_needs_an_assured_edge_a_registered_key_and_a_second_key(desk):
    desk.approve(W(INGRID), enrol(desk)["change_id"])
    desk.approve(W(INGRID), desk.propose(W(FINN), {"action": "enrol_person_key", "public_key": R.b64e(PUB), "ssh_key": SSH,
                                                   "user_verification": True})["change_id"])
    body = {"action": "grant_visit_lease", "edge": "plant-a", "person": FINN, "ssh_key": SSH, "targets": ["plc-ssh"], "hours": 48}
    r = desk.propose(W(OWNER), body)
    assert r["outcome"] == "pending" and any("second key" in x for x in r["reasons"])
    assert desk.approve(W(INGRID), r["change_id"])["outcome"] == "applied"
    too_long = desk.propose(W(OWNER), {**body, "hours": 96})
    assert too_long["outcome"] == "refused" and any("longer than 72 hours" in x for x in too_long["reasons"])
    wrong_key = desk.propose(W(OWNER), {**body, "ssh_key": SSH.replace("IBk4", "IBk5")})
    assert any("not a registered key" in x for x in wrong_key["reasons"])


def test_with_proofs_required_an_edge_enrolment_is_approved_by_a_proof_that_names_the_edge(tmp_path, monkeypatch):
    """A full-stack run of an edge implementation on 0.24.0: the security officer's statement for enrol_edge covered no records, so the
    proof vouched for nothing and the records schema refused it. Every kind the desk adds approved_by to is keyed, so
    the proof names the edge, the root signs its own enrolment as it signs any record it proposes, and the
    reconciler's check finds no edge approval without a proof."""
    from keyclerk import approvals, config, records
    from test_approvals import AUD, ISS, Broker, seed_allowlist
    broker = Broker()
    proofs = approvals.BrokerProofs({ISS}, {AUD}, 300, "https://id.test/realms/example/protocol/openid-connect/certs",
                                    tmp_path / "keys.json", fetch=broker.jwks)
    policy = {"proofs": "required", "max_age_seconds": 300, "accepted_without_proof": []}
    real = config.current
    monkeypatch.setattr(config, "current", lambda: {**real(), "approvals": policy})
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    desk = Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"), proofs=proofs,
                clock=Clock(datetime(2026, 10, 24, 8, 0, tzinfo=timezone.utc)))
    r = enrol(desk)
    own = desk.statement(W(OWNER), r["change_id"])                    # the root signs its own enrolment first
    assert own["purpose"] == "proposal" and own["records"] == ["plant-a"]
    signed = desk.approve(W(OWNER), r["change_id"], broker.token(own["nonce"], OWNER))
    assert signed["outcome"] == "pending" and any("security officer's key" in x for x in signed["reasons"]), signed
    st = desk.statement(W(INGRID), r["change_id"])
    assert st["records"] == ["plant-a"]
    done = desk.approve(W(INGRID), r["change_id"], broker.token(st["nonce"], INGRID))
    assert done["outcome"] == "applied", done
    doc = desk.store.load()
    assert doc["approval_proofs"][-1]["records"] == ["plant-a"]
    policy["accepted_without_proof"] = seed_allowlist(records.load(FIXTURES / "records.yaml"))
    assert approvals.check(doc, proofs, policy) == []
    doc["edges"][0]["approved_by"].append("idp:66cc-finn")            # a key nobody proved is found
    assert any("plant-a" in e for e in approvals.check(doc, proofs, policy))


def test_every_kind_the_desk_adds_approvals_to_is_keyed_for_proofs():
    """The 0.24.0 gap's guard: an approval the desk attaches to a kind outside approvals.KEYED is never proven."""
    import inspect
    from keyclerk import approvals
    src = inspect.getsource(Desk._with_approvals)
    kinds = set(__import__("re").findall(r'"([a-z_]+)"', src.split("for kind in", 1)[1].split(":", 1)[0]))
    assert kinds and kinds <= {k for k, _ in approvals.KEYED}
