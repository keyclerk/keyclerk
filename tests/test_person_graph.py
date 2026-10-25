# SPDX-License-Identifier: EUPL-1.2
"""The person graph (decision 0009): one person's accounts, groups, delegations and places at any moment, as far as the
view policy (Rego, compiled in) lets the viewer see; back and forward in time through the marks."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import graph, records
from keyclerk.desk import Desk, Store

FIXTURES = Path(__file__).resolve().parent / "fixtures"
W = lambda a: {"anchor": a, "roles": []}   # noqa: E731
ANN, BERT, EVA, OWNER, CARLA, DIRK = ("idp:7c1f-ann", "idp:91d0-bert", "idp:55bb-eva", "idp:2b9e-owner",
                                      "ext:3a71-carla", "idp:44aa-dirk")
VIEWER = {"anchor": None, "roles": ["keyclerk-viewer"]}


@pytest.fixture
def desk(tmp_path):
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                   encoding="utf-8")
    return Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"))


def kinds(g):
    return {n["kind"] for n in g["nodes"]}


def test_a_viewer_sees_accounts_by_source_and_the_realms_sources(desk):
    g = desk.person_graph(VIEWER, EVA)
    acc = [n for n in g["nodes"] if n["kind"] == "account"]
    assert acc and acc[0]["source"]["name"] == "Staff sign-in"
    assert {"subject", "account", "group"} <= kinds(g)
    names = {r["name"] for r in g["realm_sources"]}
    assert {"Staff sign-in", "Guest accounts", "Operator accounts"} <= names
    assert "hidden" not in g                            # never a count of what you may not see (UX C1)


def test_a_person_sees_themselves_but_not_the_realm(desk):
    g = desk.person_graph(W(EVA), EVA)
    assert "account" in kinds(g) and g["realm_sources"] is None


def test_a_manager_sees_a_member_of_their_groups_without_accounts_and_a_stranger_sees_nothing(desk):
    g = desk.person_graph(W(BERT), EVA)                 # eva is in site-heverlee, which bert manages
    assert "account" not in kinds(g) and "group" in kinds(g)
    groups = {n["label"] for n in g["nodes"] if n["kind"] == "group"}
    assert "site-heverlee" in groups and "office-staff" not in groups   # office is ann's, not bert's
    assert "hidden" not in g and len(g["nodes"]) < len(desk.person_graph(W(OWNER), EVA)["nodes"])
    with pytest.raises(PermissionError):
        desk.person_graph(W(DIRK), ANN)
    with pytest.raises(PermissionError):                # unknown answers like not-yours: no existence oracle
        desk.person_graph(W(DIRK), "idp:0000-nobody")
    with pytest.raises(LookupError):
        desk.person_graph(VIEWER, "idp:0000-nobody")


def test_back_and_forward_in_time(desk):
    now = desk.clock()
    g = desk.person_graph(VIEWER, CARLA)               # an external with a lease
    lease = [e for e in g["edges"] if e["kind"] == "lease"]
    assert lease and lease[0]["status"] == "active"
    after = desk.person_graph(VIEWER, CARLA, (datetime(2026, 10, 28, tzinfo=timezone.utc)).isoformat())
    assert [e["status"] for e in after["edges"] if e["kind"] == "lease"] == ["ended"]
    assert g["marks"]["after"] and all(m > g["at"] for m in g["marks"]["after"])
    from keyclerk.desk import Refusal
    with pytest.raises(Refusal):
        desk.person_graph(VIEWER, CARLA, (now + timedelta(days=3000)).isoformat())


def test_every_look_is_logged_without_content(desk):
    desk.person_graph(VIEWER, EVA)
    line = (desk.store.path / "views.log").read_text(encoding="utf-8").strip().splitlines()[-1]
    assert EVA in line and "Staff sign-in" not in line


def test_the_graph_names_unknown_sources_plainly():
    assert graph.source_of("zzz:1")["kind"] == "unknown"


def test_a_source_matches_by_pattern_when_anchors_have_no_prefix():
    from keyclerk import config
    cfg = config.current()
    old = cfg.get("identity_sources")
    cfg["identity_sources"] = [{"id": "entra", "name": "Partner directory", "kind": "oidc",
                                "pattern": "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"}]
    try:
        assert graph.source_of("6b1f3c2e-8d4a-4f7b-9e21-3c5d7a9b0e14")["name"] == "Partner directory"
        assert graph.source_of("idp:x")["kind"] == "unknown"
    finally:
        cfg["identity_sources"] = old
