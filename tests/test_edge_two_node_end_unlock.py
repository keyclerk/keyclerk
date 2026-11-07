# SPDX-License-Identifier: EUPL-1.2
"""A high-availability edge's second node (decision 0031) is ended and unlocked as the first is. Found by the edge
implementation reviewing its two-node design (2026-11-06): the ended notice named node 1's key only, so node 2 took the
end for an outage and kept its leases to their horizons; a phoned unlock code was always node 1's, so node 2 could
never verify one."""
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_edge_api import ANN, EVA, FINN, GINA, INGRID, OFFICER_KEY, OWNER, W, call, edge_server  # noqa: F401
from test_edges import cosigned, statement

from keyclerk import edge as E
from keyclerk import edge_records
from keyclerk.desk import Refusal

UNLOCK1, UNLOCK2 = (E.unlock_private(E.new_unlock_private()) for _ in range(2))
NODE2 = Ed25519PrivateKey.generate()


class _Proofs:
    """A stand-in for the broker's proof verifier: a token signs exactly one nonce for one person."""
    policy = {"proofs": "required"}
    resolve = None
    issued = None                                   # the sign-in's iat; now unless a test sets it

    def __call__(self, token, nonce, by):
        import time
        if token.split("#")[0] != f"signed:{nonce}:{by}":     # "#n": each sign-in is a token of its own
            raise ValueError("the token does not sign this nonce")
        return {"anchor": by, "iat": self.issued if self.issued is not None else time.time()}


def with_proofs(desk, monkeypatch):
    """Approval proofs required (phoned unlock needs them, 0.29 review S3), the broker stood in for."""
    from keyclerk.desk import Desk
    monkeypatch.setattr(Desk, "proofs_required", staticmethod(lambda: True))
    desk.store._signer.proofs = _Proofs()


def unlock(desk, who: str, edge_id: str, body: dict) -> dict:
    """A phoned unlock as an approver reads it: the statement, the approver's own fresh sign-in over it, the code."""
    st = desk.unlock_statement(W(who), edge_id, body)
    import secrets
    return desk.phoned_unlock(W(who), edge_id, body, proof=f"signed:{st['nonce']}:{who}#{secrets.token_hex(4)}")


@pytest.fixture
def two_nodes(edge_server, monkeypatch):
    """plant-u enrolled with node 1, and its record read with a second node (its own key and unlock key), as an HA
    edge's rotation states it."""
    base, desk = edge_server
    ek = Ed25519PrivateKey.generate()
    st = statement("plant-u", EVA, OFFICER_KEY, edge_key=ek, unlock=E.unlock_public(UNLOCK1))
    r = desk.propose(W(OWNER), {"action": "enrol_edge", "edge_id": "plant-u", "enrolment_key": E.public_hex(ek),
                                "officer": EVA, "officer_key": E.public_hex(OFFICER_KEY), "profile": "assured",
                                "statement": cosigned(st, OFFICER_KEY, ek), "unlock_key": E.unlock_public(UNLOCK1),
                                "unlock_approvers": [GINA, FINN],
                                "targets": [{"target": "plc-ssh", "role": "operator", "entitlement": "admin-console"}]})
    assert desk.approve(W(INGRID), r["change_id"])["outcome"] == "applied"
    real = edge_records.current
    node2 = {"enrolment_key": E.public_hex(NODE2), "unlock_key": E.unlock_public(UNLOCK2)}
    monkeypatch.setattr(edge_records, "current",
                        lambda doc, e, at: {**real(doc, e, at), "node2": node2} if e.get("edge_id") == "plant-u"
                        else real(doc, e, at))
    return base, desk, ek


def test_an_ended_two_node_edge_ends_both_nodes(two_nodes):
    base, desk, ek = two_nodes
    desk.propose(W(OWNER), {"action": "end_edge_record", "id": "plant-u", "reason": "decommissioned"})
    notice = desk.edge_ended("plant-u")
    pins = {"edge": "plant-u", "bundle_key": call(base, "GET", "/edge-key", signed=False)[1]["key"]}
    assert E.verify_ended(notice, pins, E.public_hex(ek))[0] == []
    assert E.verify_ended(notice, pins, E.public_hex(NODE2))[0] == []             # node 2 stops and wipes too


BODY = {"person": ANN, "target": "plc-ssh", "key_fingerprint": "SHA256:abc", "nonce": "n-1", "minutes": 30}


def test_a_phoned_unlock_names_the_node_and_uses_that_nodes_unlock_key(two_nodes, monkeypatch):
    base, desk, ek = two_nodes
    with_proofs(desk, monkeypatch)
    with pytest.raises(Refusal, match="two nodes"):
        unlock(desk, GINA, "plant-u", BODY)
    with pytest.raises(Refusal, match="not a node"):
        unlock(desk, GINA, "plant-u", {**BODY, "node": "0" * 16})
    node = E.key_id(E.public_hex(NODE2))
    out = unlock(desk, GINA, "plant-u", {**BODY, "node": node})
    desk_pub = call(base, "GET", "/edge-key", signed=False)[1]["unlock_key"]
    on_node2 = E.unlock_code(E.unlock_secret(UNLOCK2, desk_pub, E.unlock_public(UNLOCK2), "plant-u", node),
                             "plant-u", node, ANN, "SHA256:abc", "plc-ssh", "n-1", 30)
    assert out["node"] == node and out["code"] == on_node2                        # node 2 computes the same code
    n1 = E.key_id(E.public_hex(ek))
    out1 = unlock(desk, FINN, "plant-u", {**BODY, "node": n1})
    on_node1 = E.unlock_code(E.unlock_secret(UNLOCK1, desk_pub, E.unlock_public(UNLOCK1), "plant-u", n1),
                             "plant-u", n1, ANN, "SHA256:abc", "plc-ssh", "n-1", 30)
    assert out1["code"] == on_node1 != out["code"]


def test_a_desk_that_skips_its_checks_still_gets_no_code_it_should_not(two_nodes, monkeypatch):
    """0021: the unlock key is the signer's, and so are the checks. A taken-over desk asking the signer directly for a
    code from someone who is not an unlock approver, or for the approver themselves, or past the hourly count, gets
    a refusal, whatever the desk itself checked."""
    from keyclerk.signer import SignerRefused
    base, desk, ek = two_nodes
    with_proofs(desk, monkeypatch)
    signer = desk.store._signer
    node = E.key_id(E.public_hex(NODE2))

    def ask(approver, person=ANN):
        import secrets

        from keyclerk.approvals import unlock_statement
        realm = desk.store.load()["realm"]
        st = unlock_statement(realm, "plant-u", node, approver, person, "plc-ssh", "SHA256:abc", "n-1", 30)
        return signer.unlock({"edge_id": "plant-u", "fields": {"approver": approver, "person": person,
                                                               "target": "plc-ssh", "key_fingerprint": "SHA256:abc",
                                                               "nonce": "n-1", "minutes": 30, "node": node,
                                                               "proof": f"signed:{st}:{approver}#{secrets.token_hex(4)}"}})
    with pytest.raises(SignerRefused, match="only an unlock approver"):
        ask(ANN)
    with pytest.raises(SignerRefused, match="never unlocks themselves"):
        ask(GINA, person=GINA)
    from keyclerk import policy_wasm
    per_hour = int(policy_wasm.edge("settings", {})["unlock_per_hour"])
    for _ in range(per_hour):
        assert ask(GINA)["code"]
    with pytest.raises(SignerRefused, match="an hour"):
        ask(FINN)


def test_without_approval_proofs_no_unlock_code_is_computed(edge_server, monkeypatch):
    """0.29 review S3: without proofs the signer computed any code on the desk's word; now it refuses, and the desk
    says how to enable proofs."""
    from keyclerk.desk import Desk
    from keyclerk.signer import SignerRefused
    base, desk = edge_server
    monkeypatch.setattr(Desk, "proofs_required", staticmethod(lambda: False))
    with pytest.raises(Refusal, match="needs approval proofs"):
        desk.phoned_unlock(W(GINA), "plant-u", BODY)
    with pytest.raises(SignerRefused, match="needs approval proofs"):
        desk.store._signer.unlock({"edge_id": "plant-u", "fields": {}})


def test_with_proofs_required_an_unlock_is_the_approvers_own_fresh_signature(two_nodes, monkeypatch):  # noqa: F811
    """0021 step 4b: where approval proofs are required, the approver's fresh sign-in signs this one unlock (the
    statement over every field of the code); the signer checks it before it computes the code."""
    base, desk, ek = two_nodes
    from keyclerk.desk import Desk
    monkeypatch.setattr(Desk, "proofs_required", staticmethod(lambda: True))
    desk.store._signer.proofs = _Proofs()
    body = {**BODY, "node": E.key_id(E.public_hex(NODE2))}
    with pytest.raises(Refusal, match="sign in again"):
        desk.phoned_unlock(W(GINA), "plant-u", body)
    st = desk.unlock_statement(W(GINA), "plant-u", body)
    assert st["by"] == GINA and st["edge"] == "plant-u"
    out = desk.phoned_unlock(W(GINA), "plant-u", body, proof=f"signed:{st['nonce']}:{GINA}")
    assert out["code"]
    other = desk.unlock_statement(W(GINA), "plant-u", {**body, "minutes": 5})["nonce"]
    with pytest.raises(Refusal, match="does not sign this unlock"):              # a proof for another unlock
        desk.phoned_unlock(W(GINA), "plant-u", body, proof=f"signed:{other}:{GINA}")
    with pytest.raises(Refusal, match="does not sign this unlock"):              # another person's sign-in
        desk.phoned_unlock(W(GINA), "plant-u", body, proof=f"signed:{st['nonce']}:{FINN}")
