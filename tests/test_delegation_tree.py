# SPDX-License-Identifier: EUPL-1.2
"""The delegation tree (decision 0009, section 8): what was handed on, to whom, how deep and until when, at any moment,
as far as the tree policy (Rego, compiled in) lets the viewer see."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk.desk import Desk, Refusal, Store

FIXTURES = Path(__file__).resolve().parent / "fixtures"
W = lambda a: {"anchor": a, "roles": []}   # noqa: E731
ANN, BERT, EVA, OWNER, DIRK = "idp:7c1f-ann", "idp:91d0-bert", "idp:55bb-eva", "idp:2b9e-owner", "idp:44aa-dirk"
VIEWER = {"anchor": None, "roles": ["keyclerk-viewer"]}
D1, D2, D3 = "D-example-0001", "D-example-0002", "D-example-0003"
OCT15, OCT23, APR15 = "2026-10-15T00:00:00Z", "2026-10-23T00:00:00Z", "2027-04-15T00:00:00Z"


@pytest.fixture
def desk(tmp_path):
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                   encoding="utf-8")
    return Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"))


def ids(t):
    return {n["id"] for n in t["nodes"]}


def by_id(t):
    return {n["id"]: n for n in t["nodes"]}


def test_a_viewer_and_the_root_see_the_whole_tree(desk):
    for who in (VIEWER, W(OWNER)):
        t = desk.delegation_tree(who, OCT15)
        assert ids(t) == {"root", D1, D2, D3} and t["whole"]
    assert {(e["source"], e["target"]) for e in t["edges"]} == {("root", D1), ("root", D2), (D2, D3)}
    n = by_id(t)
    assert n[D3]["depth"] == 2 and n[D3]["by"] == "bert" and n[D3]["label"] == "dirk" and n[D3]["in_use"] == 1


def test_a_deputy_sees_what_they_handed_on_and_the_chain_above_but_not_siblings(desk):
    t = desk.delegation_tree(W(BERT), OCT15)
    assert ids(t) == {"root", D2, D3} and not t["whole"] and t["held"] == [D2]
    assert ids(desk.delegation_tree(W(DIRK), OCT15)) == {"root", D2, D3}
    assert ids(desk.delegation_tree(W(ANN), OCT15)) == {"root", D1}


def test_someone_holding_no_delegation_sees_an_empty_tree(desk):
    t = desk.delegation_tree(W(EVA), OCT15)
    assert t["nodes"] == [] and t["edges"] == [] and t["held"] == []


def test_back_and_forward_in_time(desk):
    assert by_id(desk.delegation_tree(VIEWER, OCT15))[D3]["status"] == "active"
    retired = by_id(desk.delegation_tree(VIEWER, OCT23))[D3]               # retired 2026-10-20: grace runs
    assert retired["status"] == "grace" and retired["grace_until"].startswith("2026-11-03")
    later = desk.delegation_tree(VIEWER, APR15)
    assert D3 not in ids(later)                                             # stopped long before: left out
    assert by_id(later)[D1]["status"] == "ended"
    t = desk.delegation_tree(VIEWER, OCT23)
    assert any(m.startswith("2026-11-03") for m in t["marks"]["after"])      # the grace end is a step
    with pytest.raises(Refusal):
        desk.delegation_tree(VIEWER, "2036-01-01T00:00:00Z")


def test_every_look_at_the_tree_is_logged(desk):
    desk.delegation_tree(W(BERT), OCT15)
    line = (desk.store.path / "views.log").read_text(encoding="utf-8").strip().splitlines()[-1]
    assert "delegation-tree" in line and BERT in line and "dirk" not in line
