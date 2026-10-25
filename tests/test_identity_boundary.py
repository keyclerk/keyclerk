# SPDX-License-Identifier: EUPL-1.2
"""Decision 0028 at the desk on the change log (S5 step T4): people cross the boundary once. A request or a sign-in
that names someone by the identity provider's id is translated through the mapping; the log names everyone by an
internal anchor that an accounts record vouches for; a link keeps an entry's structure, never its free text; the
signer refuses anything else. On the signed YAML store nothing changes."""
import json
import re

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_signer_replica import FIXTURES

from keyclerk import anchors as A
from keyclerk import records
from keyclerk.desk import Desk, Store
from keyclerk.oidc import Oidc
from keyclerk.signer import Signer, SignerRefused
from keyclerk.store import link as L
from keyclerk.store import migrate as M
from keyclerk.store import replay as RP
from keyclerk.store.log_desk import LINK_ENTRY, LogStore

ANN = {"anchor": "idp:7c1f-ann", "roles": []}
ADD = {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 5,
       "reason": "Finn starts on the helpdesk"}


@pytest.fixture
def log(tmp_path):
    signer = Signer(Ed25519PrivateKey.generate(), tmp_path / "signer")
    store = LogStore(tmp_path / "desk", signer, FIXTURES / "records.yaml")
    yield {"signer": signer, "store": store, "desk": Desk(store)}
    store.close()
    signer.close()


def _bodies(log):
    return [L.open_link(x, log["signer"].public_key())[0] for x in log["store"].store.links()]


def test_a_request_by_provider_ids_is_kept_by_internal_anchors(log):
    st = log["store"]
    r = log["desk"].propose(ANN, ADD)
    assert r["outcome"] == "applied"
    finn, ann = st.inward("idp:66cc-finn"), st.inward("idp:7c1f-ann")
    m = r["records"]["memberships"][0]
    assert A.is_internal(finn) and m["member"]["anchor"] == finn and m["by"] == ann
    assert m in st.load()["memberships"]
    entry = _bodies(log)[-1]["change"]["entry"]
    assert entry["actor"] == ann and set(entry) <= set(LINK_ENTRY)


def test_no_link_names_anyone_by_a_provider_id_or_a_label(log):
    log["desk"].propose(ANN, ADD)
    labels = [p["person"] for p in records.load(FIXTURES / "records.yaml")["persons"]]
    for body in _bodies(log):
        text = json.dumps(body)
        assert not re.findall(r"idp:[0-9a-z-]+", text)
        entry = json.dumps(body["change"]["entry"])
        assert not [x for x in labels if re.search(rf"\b{re.escape(x)}\b", entry)], entry[:200]
    assert "add finn to office-staff" in json.dumps(log["store"].log(5))     # the activity log keeps the summary


def test_every_internal_anchor_of_the_log_is_a_vouched_account(log):
    st = log["store"]
    doc = RP.records(st.store)
    accounts = {a["anchor"]: a["commit"] for a in doc["accounts"]}
    rows = dict(st.store.side_scan("anchor_map"))
    named = {v for kind in records.ANCHOR_PATHS for rec in (doc.get(kind) if isinstance(doc.get(kind), list)
                                                             else [doc.get(kind)] if isinstance(doc.get(kind), dict) else [])
             for _, v in records.anchor_values(kind, rec) if A.is_internal(v)}
    assert named and named <= set(accounts) == set(rows)
    assert all(A.row_matches(rows[a], [c]) for a, c in accounts.items())
    persons = {a for p in doc["persons"] for a in A.accounts(p)}
    assert set(accounts) - persons                       # accounts with no person record are vouched for too


def test_the_signer_refuses_a_provider_id_whatever_the_desk_sends(log):
    s, st = log["signer"], log["store"]
    m = dict(next(iter(st.store.scan("memberships")))[1])
    m["member"] = {"anchor": "idp:66cc-finn"}
    op = {"op": "put", "kind": "memberships", "key": m["membership_id"], "record": m}
    with pytest.raises(SignerRefused, match="not by an internal anchor"):
        s.propose(st.follower.base(), {"ops": [op], "entry": {"change_id": "C-a11ce0"}}, [])
    m["member"] = {"anchor": A.new()}                   # internal, but no account stands for it
    with pytest.raises(SignerRefused, match="no account of the log"):
        s.propose(st.follower.base(), {"ops": [{**op, "record": m}], "entry": {"change_id": "C-a11ce1"}}, [])


def test_sign_in_resolves_through_the_mapping_in_two_phases(log):
    st = log["store"]
    auth = Oidc("https://id.test/realms/example", "https://id.test/realms/example", "keyclerk", "https://desk.test/cb",
                "keyclerk-viewer")
    assert auth.anchor_of({"anchor": "idp:7c1f-ann"}) == "idp:7c1f-ann"                # the YAML store: the claim
    auth.resolve = lambda claims: A.resolve(st.store, claims)
    ann = st.inward("idp:7c1f-ann")
    assert auth.anchor_of({"anchor": "idp:7c1f-ann", "sub": "u-ann"}) == ann           # phase 1: the legacy claim
    row = st.store.side_get("anchor_map", ann)
    st.store.side_put("anchor_map", ann, {**row, "sub": "u-ann"})                     # the reconciler linked her
    st.store.side_put("anchor_idp", A.sub_key("u-ann"), {"anchor": ann})
    assert auth.anchor_of({"sub": "u-ann"}) == ann                                      # phase 2: by subject only
    assert auth.anchor_of({"anchor": "idp:7c1f-ann", "sub": "u-mallory"}) is None       # a moved attribute: nobody
    assert auth.anchor_of({}, {"sub": "u-ann"}) == ann                                  # the first set naming someone


def test_the_yaml_store_names_people_as_given(tmp_path):
    key = tmp_path / "key"
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                   encoding="utf-8")
    d = Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"))
    try:
        assert d.store.inward("idp:66cc-finn") == "idp:66cc-finn"
        d.propose(ANN, ADD)
        assert any(m["member"].get("anchor") == "idp:66cc-finn" for m in d.store.load()["memberships"])
        assert "accounts" not in d.store.load()
    finally:
        d.store.close()


def test_the_migration_and_the_seed_vouch_for_the_same_accounts(log, tmp_path):
    seed = records.load(FIXTURES / "records.yaml")
    rows = M.mint_rows(seed)
    assert {r["idp"] for r in rows} == {r["idp"] for _, r in log["store"].store.side_scan("anchor_map")}
