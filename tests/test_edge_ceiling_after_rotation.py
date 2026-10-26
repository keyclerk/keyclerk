# SPDX-License-Identifier: EUPL-1.2
"""After a rotation to another officer or key, the old officer's ceiling governs nothing until the new one signs."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from tests.test_edges import desk, EDGE_KEY, EVA, INGRID, OFFICER_KEY, OWNER, W, FINN, cosigned, enrol, statement  # noqa: F401
from tests.test_edge_api import ceiling


def test_a_replaced_officers_ceiling_no_longer_governs(desk):
    assert desk.approve(W(INGRID), enrol(desk)["change_id"])["outcome"] == "applied"
    desk.set_ceiling(W(EVA), "plant-a", {"ceiling": E.seal_ceiling(OFFICER_KEY, ceiling())})
    before = E.unseal(desk.edge_bundle("plant-a"), E.public_hex(desk.bundle_key), E.BUNDLE_FORMAT)
    assert before["leases"]                                                    # leases under Eva's ceiling
    new_officer_key = Ed25519PrivateKey.generate()                             # Eva replaced by Finn
    st = statement("plant-a", FINN, new_officer_key, edge_key=EDGE_KEY, purpose="rotation")
    r = desk.propose(W(OWNER), {"action": "rotate_edge", "edge_id": "plant-a", "enrolment_key": E.public_hex(EDGE_KEY),
                                "officer": FINN, "officer_key": E.public_hex(new_officer_key),
                                "statement": cosigned(st, new_officer_key, EDGE_KEY)})
    assert desk.approve(W(INGRID), r["change_id"])["outcome"] == "applied"
    after = E.unseal(desk.edge_bundle("plant-a"), E.public_hex(desk.bundle_key), E.BUNDLE_FORMAT)
    c = after["ceiling"]
    assert c is None or c["key"] == E.public_hex(new_officer_key), \
        f"bundle still carries the replaced officer's ceiling and {len(after['leases'])} lease(s) under it"
