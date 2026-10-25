# SPDX-License-Identifier: EUPL-1.2
"""Migrating a running desk to the signed change log (decision 0022 S5 step T7): the desk's replica built where the
log store opens it, its pending changes re-keyed so they can still be approved, its YAML-era activity log moved aside,
and its history starting with one line that says where it came from."""
import json
import re

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_signer_replica import FIXTURES

from keyclerk import anchors as A
from keyclerk.desk import Desk, Store
from keyclerk.signer import Signer
from keyclerk.store import migrate as M
from keyclerk.store.link import StoreRefused, open_link
from keyclerk.store.log_desk import LogStore

ANN, EVA = {"anchor": "idp:7c1f-ann", "roles": []}, {"anchor": "idp:55bb-eva", "roles": []}
ADD = {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 30}


def _needs_eva(monkeypatch, name):
    """A rule the test adds: a new membership of finn in office-staff needs eva's key (named as the store holds them)."""
    real = Desk._errors

    def errors(self, doc):
        out = set(real(self, doc))
        finn, eva = (self.store.inward(a) or a for a in ("idp:66cc-finn", "idp:55bb-eva"))
        for m in doc.get("memberships", []):
            if m["member"].get("anchor") == finn and m["group"] == "office-staff" and eva not in m.get("approved_by", []):
                out.add(f"{m['membership_id']}: {name}")
        return out
    monkeypatch.setattr(Desk, "_errors", errors)
    monkeypatch.setattr(LogStore, "scoped_judging", False)    # the rule is added to the full check: judge in full


@pytest.fixture
def migrated(tmp_path, monkeypatch):
    signer = Signer(Ed25519PrivateKey.generate(), tmp_path / "signer")
    desk_dir = tmp_path / "desk"
    yaml_desk = Desk(Store(desk_dir, None, FIXTURES / "records.yaml", signer=signer))
    _needs_eva(monkeypatch, "needs a second key")
    pending = yaml_desk.propose(ANN, ADD)
    assert pending["outcome"] == "pending"
    revision = yaml_desk.store.revision()
    yaml_desk.store.close()
    got = M.migrate_desk_store(desk_dir, desk_dir / "log.db", signer=signer)
    yield {"signer": signer, "dir": desk_dir, "got": got, "cid": pending["change_id"], "revision": revision}
    signer.close()


def test_the_desk_opens_on_the_log_at_the_signers_head(migrated):
    st = LogStore(migrated["dir"], migrated["signer"])
    try:
        assert st.store.head() == migrated["signer"].replica.head() and st.revision() == migrated["revision"]
        assert migrated["got"]["pending"] == 1 and not st.verify_log()
    finally:
        st.close()


def test_the_history_starts_with_one_line_saying_where_it_came_from(migrated):
    st = LogStore(migrated["dir"], migrated["signer"])
    try:
        lines = st.log(100)
        assert [x["action"] for x in lines] == ["migrated"]
        assert lines[0]["from_revision"] == migrated["revision"]
        assert lines[0]["summary"] == f"migrated from signed YAML revision {migrated['revision']}"
        assert (migrated["dir"] / "log-yaml.jsonl").exists()        # the YAML era, moved aside for the purge
    finally:
        st.close()


def test_pending_changes_are_rekeyed_and_can_still_be_approved(migrated, monkeypatch):
    raw = json.loads((migrated["dir"] / "pending.json").read_text(encoding="utf-8"))
    p = raw[migrated["cid"]]
    assert A.is_internal(p["actor"]) and all(A.is_internal(a) for a in p["waiting_for"])
    assert A.is_internal(p["records"]["memberships"][0]["member"]["anchor"])
    assert not re.findall(r"idp:[0-9a-z-]+", json.dumps(p))
    assert "idp:" in (migrated["dir"] / "pending-yaml.json").read_text(encoding="utf-8")   # kept for the purge
    st = LogStore(migrated["dir"], migrated["signer"])
    try:
        d = Desk(st)
        done = d.approve(EVA, migrated["cid"])
        assert done["outcome"] == "applied"
        for sealed in st.store.links():
            assert not re.findall(r"idp:[0-9a-z-]+", json.dumps(open_link(sealed, migrated["signer"].public_key())[0]))
    finally:
        st.close()


def test_a_desk_migrated_once_is_not_migrated_again(migrated):
    with pytest.raises(StoreRefused, match="exists"):
        M.migrate_desk_store(migrated["dir"], migrated["dir"] / "log.db", signer=migrated["signer"])
    with pytest.raises(StoreRefused, match="migrated before"):
        M.finish_desk(migrated["dir"], migrated["signer"], migrated["revision"])


def test_rekeyed_pending_keeps_unknown_names_and_every_field(tmp_path):
    rows = [A.mapping_row("idp:7c1f-ann"), A.mapping_row("idp:55bb-eva")]
    ann, eva = rows[0]["anchor"], rows[1]["anchor"]
    p = {"C-b0c1d2": {"action": "x", "actor": "idp:7c1f-ann", "approvals": ["idp:55bb-eva"], "waiting_for": ["idp:99zz-new"],
                 "records": {"memberships": [{"membership_id": "M-1", "member": {"anchor": "idp:99zz-new"},
                                              "by": "idp:7c1f-ann", "group": "g"}]}, "summary": "s"}}
    q = M.rekeyed_pending(p, rows)["C-b0c1d2"]
    assert q["actor"] == ann and q["approvals"] == [eva] and q["waiting_for"] == ["idp:99zz-new"]
    assert q["records"]["memberships"][0] == {"membership_id": "M-1", "member": {"anchor": "idp:99zz-new"}, "by": ann,
                                               "group": "g"}
    assert set(q) == set(p["C-b0c1d2"])
