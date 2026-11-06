# SPDX-License-Identifier: EUPL-1.2
"""A high-availability edge's second node (decision 0031) is ended and unlocked as the first is. Found by the edge
implementation reviewing its two-node design (2026-11-06): the ended notice named node 1's key only, so node 2 took the
end for an outage and kept its leases to their horizons; a phoned unlock code was always node 1's, so node 2 could
never verify one."""
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from keyclerk import edge_records
from keyclerk.desk import Refusal

from test_edge_api import ANN, EVA, FINN, GINA, INGRID, OFFICER_KEY, OWNER, W, call, edge_server  # noqa: F401
from test_edges import cosigned, statement

UNLOCK1, UNLOCK2 = (E.unlock_private(E.new_unlock_private()) for _ in range(2))
NODE2 = Ed25519PrivateKey.generate()


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


def test_a_phoned_unlock_names_the_node_and_uses_that_nodes_unlock_key(two_nodes):
    base, desk, ek = two_nodes
    with pytest.raises(Refusal, match="two nodes"):
        desk.phoned_unlock(W(GINA), "plant-u", BODY)
    with pytest.raises(Refusal, match="not a node"):
        desk.phoned_unlock(W(GINA), "plant-u", {**BODY, "node": "0" * 16})
    node = E.key_id(E.public_hex(NODE2))
    out = desk.phoned_unlock(W(GINA), "plant-u", {**BODY, "node": node})
    desk_pub = call(base, "GET", "/edge-key", signed=False)[1]["unlock_key"]
    on_node2 = E.unlock_code(E.unlock_secret(UNLOCK2, desk_pub, E.unlock_public(UNLOCK2), "plant-u", node),
                             "plant-u", node, ANN, "SHA256:abc", "plc-ssh", "n-1", 30)
    assert out["node"] == node and out["code"] == on_node2                        # node 2 computes the same code
    n1 = E.key_id(E.public_hex(ek))
    out1 = desk.phoned_unlock(W(FINN), "plant-u", {**BODY, "node": n1})
    on_node1 = E.unlock_code(E.unlock_secret(UNLOCK1, desk_pub, E.unlock_public(UNLOCK1), "plant-u", n1),
                             "plant-u", n1, ANN, "SHA256:abc", "plc-ssh", "n-1", 30)
    assert out1["code"] == on_node1 != out["code"]
