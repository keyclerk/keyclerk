# SPDX-License-Identifier: EUPL-1.2
"""Decision 0014 on the change log (decision 0022): a desk that judges a change on what it reaches loads the people an
edge record names (its officer and custodians, a visit lease's person), so an enrolment, a person key and a visit
lease go through as they do on a YAML desk. Found by the core-side soak harness: the working set read people only
from a hand-kept list of person fields, which named none of the edge kinds' fields."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from keyclerk import relay as R
from keyclerk.desk import Desk, Store
from keyclerk.signer import Signer
from keyclerk.store.log_desk import LogStore

from test_edges import SSH
from test_visits import FIXTURES


def test_an_edge_its_person_keys_and_a_visit_lease_on_a_log_backed_desk(tmp_path):
    key = Ed25519PrivateKey.generate()
    signer = Signer(key, tmp_path / "signer")
    Store(tmp_path / "seed", None, FIXTURES / "records.yaml", signer=signer).close()
    signer.migrate()
    signer.background_check()
    store = LogStore(tmp_path / "desk", signer)
    try:
        desk = Desk(store)
        a = {p["person"]: p["anchors"][0] for p in store.load()["persons"]}   # internal anchors (decision 0028)
        w = lambda n: {"anchor": a[n], "roles": []}                           # noqa: E731
        officer, edge_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        st = E.officer_statement("plant-a", a["eva"], E.public_hex(officer),
                                 [E.node(E.public_hex(edge_key), None, None)], "enrolment")
        r = desk.propose(w("owner"), {
            "action": "enrol_edge", "edge_id": "plant-a", "enrolment_key": E.public_hex(edge_key), "officer": a["eva"],
            "officer_key": E.public_hex(officer), "profile": "assured", "statement": E.cosign(edge_key, E.cosign(officer, st)),
            "custodians": [a["finn"], a["gina"]],
            "targets": [{"target": "plc-ssh", "role": "operator", "entitlement": "admin-console", "max_session_hours": 2}]})
        assert r["outcome"] == "pending" and r["reasons"] == ["plant-a: enrolling an edge needs the security officer's key"]
        assert desk.approve(w("ingrid"), r["change_id"])["outcome"] == "applied"
        _, pub = R.person_key_from_prf(b"\x11" * 32)
        r = desk.propose(w("finn"), {"action": "enrol_person_key", "public_key": R.b64e(pub), "ssh_key": SSH,
                                     "user_verification": True})
        assert desk.approve(w("ingrid"), r["change_id"])["outcome"] == "applied"
        r = desk.propose(w("owner"), {"action": "grant_visit_lease", "edge": "plant-a", "person": a["finn"],
                                      "ssh_key": SSH, "targets": ["plc-ssh"], "hours": 2})
        assert r["outcome"] == "pending" and any("second key" in x for x in r["reasons"])
        assert desk.approve(w("ingrid"), r["change_id"])["outcome"] == "applied"
        assert [v["person"] for v in store.load()["edge_visit_leases"]] == [a["finn"]]
    finally:
        store.close()
        signer.close()
