# SPDX-License-Identifier: EUPL-1.2
"""A rotation meets the enrolment's rules for its keys and officer."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from tests.test_edges import desk, EDGE_KEY, EVA, INGRID, OFFICER_KEY, OWNER, W, FINN, cosigned, enrol, statement  # noqa: F401

CARLA = "ext:3a71-carla"          # an external person in the fixture


def _enrol_b(desk, key_b):
    st = statement("plant-b", EVA, OFFICER_KEY, edge_key=key_b)
    r = desk.propose(W(OWNER), {"action": "enrol_edge", "edge_id": "plant-b", "enrolment_key": E.public_hex(key_b),
                                "officer": EVA, "officer_key": E.public_hex(OFFICER_KEY), "profile": "assured",
                                "statement": cosigned(st, OFFICER_KEY, key_b), "custodians": [FINN, "idp:77dd-gina"],
                                "targets": [{"target": "plc-ssh", "role": "operator", "entitlement": "admin-console"}]})
    assert desk.approve(W(INGRID), r["change_id"])["outcome"] == "applied"


def _rotate(desk, edge_id, new_key, officer, officer_key):
    st = statement(edge_id, officer, officer_key, edge_key=new_key, purpose="rotation")
    r = desk.propose(W(OWNER), {"action": "rotate_edge", "edge_id": edge_id, "enrolment_key": E.public_hex(new_key),
                                "officer": officer, "officer_key": E.public_hex(officer_key),
                                "statement": cosigned(st, officer_key, new_key)})
    if r["outcome"] == "pending":
        r = desk.approve(W(INGRID), r["change_id"])
    return r


def test_a_rotation_cannot_give_an_edge_another_edges_enrolment_key(desk):
    assert desk.approve(W(INGRID), enrol(desk)["change_id"])["outcome"] == "applied"      # plant-a: EDGE_KEY
    _enrol_b(desk, Ed25519PrivateKey.generate())
    r = _rotate(desk, "plant-b", EDGE_KEY, EVA, OFFICER_KEY)
    assert r["outcome"] == "refused", "plant-b rotated onto plant-a's enrolment key"
    # (if applied: desk.edge_public_of('plant-a') == desk.edge_public_of('plant-b'): one key signs for both edges)


def test_a_rotation_cannot_name_an_external_as_the_edges_officer(desk):
    assert desk.approve(W(INGRID), enrol(desk)["change_id"])["outcome"] == "applied"
    carla_key = Ed25519PrivateKey.generate()
    r = _rotate(desk, "plant-a", Ed25519PrivateKey.generate(), CARLA, carla_key)
    assert r["outcome"] == "refused", "an external person became the edge's officer by rotation"
