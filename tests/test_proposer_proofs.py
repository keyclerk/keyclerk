# SPDX-License-Identifier: EUPL-1.2
"""Decision 0015 (replan D2): a high-risk change carries its proposer's own signature, a fresh sign-in at the broker,
not only the desk's word; low-risk changes stay desk-vouched; the checking signer refuses a revision that adds or widens
a high-risk record without it."""
import copy
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import approvals, records
from keyclerk.desk import Desk, Refusal, Store
from keyclerk.signer import Signer, SignerClient, SignerRefused, serve
from tests.test_approvals import ANN, BERT, FIXTURES, W, broker, proofs, required  # noqa: F401 - fixtures

FINN = "idp:66cc-finn"


def test_a_low_risk_change_stays_desk_vouched(tmp_path, proofs, required):
    required()
    desk = Desk(Store(tmp_path / "store", None, FIXTURES / "records.yaml", signer=_inproc(tmp_path)), proofs=proofs)
    r = desk.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": FINN, "days": 5})
    assert r["outcome"] == "applied"


def test_a_high_risk_change_waits_for_its_proposer_who_signs_it_at_the_broker(tmp_path, broker, proofs, required):
    required()
    desk = Desk(Store(tmp_path / "store", None, FIXTURES / "records.yaml", signer=_inproc(tmp_path)), proofs=proofs)
    r = desk.propose(ANN, {"action": "add_member", "group": "finance", "anchor": FINN, "days": 5})
    assert r["outcome"] == "pending" and any("your own signature" in x for x in r["reasons"])
    view = next(c for c in desk.changes(ANN)["pending"] if c["change_id"] == r["change_id"])
    assert view["can_sign"] and not view["can_approve"]
    st = desk.statement(ANN, r["change_id"])
    assert st["purpose"] == "proposal"
    approval_nonce = approvals.statement(desk.store.load()["realm"],
                                         [(k, x) for k, _ in approvals.KEYED for x in r["records"].get(k, [])], "idp:7c1f-ann")
    assert approval_nonce != st["nonce"]                                   # the purpose is part of what is signed
    with pytest.raises(Refusal, match="your own signature"):
        desk.approve(ANN, r["change_id"])
    with pytest.raises(Refusal, match="does not fit"):
        desk.approve(ANN, r["change_id"], broker.token(approval_nonce, "idp:7c1f-ann"))
    done = desk.approve(ANN, r["change_id"], broker.token(st["nonce"], "idp:7c1f-ann"))
    assert done["outcome"] == "applied", done["reasons"]
    doc = desk.store.load()
    assert doc["proposal_proofs"][0]["by"] == "idp:7c1f-ann"
    assert all("token" not in p for p in done["records"]["proposal_proofs"])    # answers show a hash, never the token


def test_the_signer_refuses_a_high_risk_record_without_its_proposers_proof(tmp_path, broker, proofs, required):
    policy = required()
    key = Ed25519PrivateKey.generate()
    signer = Signer(key, tmp_path / "state", proofs)
    signer.proofs.policy = policy
    raw = (FIXTURES / "records.yaml").read_text(encoding="utf-8")
    doc = records.loads(raw)
    signer.adopt(raw, key.sign(raw.encode("utf-8")).hex())
    new = copy.deepcopy(doc)
    new["revision"] = int(doc.get("revision") or 0) + 1
    m = {"membership_id": "M-example-0900", "group": "finance", "member": {"anchor": FINN}, "by": "idp:7c1f-ann",
         "under": "D-example-0001", "start": doc["memberships"][0]["start"], "end": doc["memberships"][0]["end"]}
    new["memberships"].append(m)
    assert approvals.check_proposals(doc, new, proofs, policy)            # no proof: refused
    nonce = approvals.statement(new["realm"], [("memberships", m)], "idp:7c1f-ann", purpose="proposal")
    new["proposal_proofs"] = [{"records": [m["membership_id"]], "by": "idp:7c1f-ann", "token": broker.token(nonce, "idp:7c1f-ann")}]
    assert approvals.check_proposals(doc, new, proofs, policy) == []
    forged = copy.deepcopy(new)
    forged["proposal_proofs"][0]["token"] = broker.token(nonce, "idp:91d0-bert")
    assert approvals.check_proposals(doc, forged, proofs, policy)          # someone else's sign-in
    ended = copy.deepcopy(doc)
    ended["memberships"][0]["end"] = ended["memberships"][0]["start"]      # ending sooner needs no second signature
    assert not list(approvals.widened(doc, ended))


def _inproc(tmp_path):
    """A checking signer on a loopback socket, as the desk would use it."""
    key = Ed25519PrivateKey.generate()
    tok = tmp_path / "token"
    tok.write_text("t0ken-for-tests", encoding="utf-8")
    srv = serve(Signer(key, tmp_path / "signer-state"), "tcp:127.0.0.1:0", "t0ken-for-tests")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return SignerClient(f"tcp:127.0.0.1:{srv.server_address[1]}", str(tok))


def test_the_preview_says_a_high_risk_change_waits_for_its_proposer(tmp_path, proofs, required):
    required()
    desk = Desk(Store(tmp_path / "store", None, FIXTURES / "records.yaml", signer=_inproc(tmp_path)), proofs=proofs)
    p = desk.preview(ANN, {"action": "add_member", "group": "finance", "anchor": FINN, "days": 5})
    assert p["outcome"] == "pending" and any("your own signature" in x for x in p["reasons"])
    assert desk.store.revision() == 1                                       # a preview changes nothing


def test_an_approval_that_does_not_count_is_refused_and_says_why(tmp_path, broker, proofs, required):
    """A key that does not count only adds "; X does not count: why" to the reason it leaves open: the approval is
    refused with that reason, and the change waits as it did (found in a full-stack run, 2026-10-26: such an approval
    answered pending, so the approver saw no change and no why)."""
    required()
    desk = Desk(Store(tmp_path / "store", None, FIXTURES / "records.yaml", signer=_inproc(tmp_path)), proofs=proofs)
    root, officer = W("idp:2b9e-owner"), W("idp:31ee-ingrid")
    r = desk.propose(root, {"action": "add_member", "group": "admins", "anchor": "idp:31ee-ingrid", "days": 1})
    cid = r["change_id"]
    signed = desk.approve(root, cid, broker.token(desk.statement(root, cid)["nonce"], "idp:2b9e-owner"))
    assert signed["outcome"] == "pending" and not any("your own signature" in x for x in signed["reasons"])
    with pytest.raises(Refusal, match="does not count as a key.*idp:31ee-ingrid does not count: the member"):
        desk.approve(officer, cid, broker.token(desk.statement(officer, cid)["nonce"], "idp:31ee-ingrid"))
    assert desk.store.pending()[cid]["approvals"] == []
    done = desk.approve(BERT, cid, broker.token(desk.statement(BERT, cid)["nonce"], "idp:91d0-bert"))
    assert done["outcome"] == "applied", done["reasons"]
