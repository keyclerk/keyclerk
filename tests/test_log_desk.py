# SPDX-License-Identifier: EUPL-1.2
"""The desk on the signed change log (decision 0022, S5 step T3): what only the log store does. The desk's own
behaviour on it is test_desk and test_visits, which run on both stores."""
import copy
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_signer_replica import FIXTURES, world  # noqa: F401 - world is a fixture

from keyclerk.desk import Desk, StoreFault
from keyclerk.signer import Signer, SignerRefused
from keyclerk.store import replay as RP
from keyclerk.store.log_desk import LogStore, ops_between

ANN = {"anchor": "idp:7c1f-ann", "roles": []}
ADD = {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 5}


@pytest.fixture
def started(tmp_path):
    """A signer started empty and a desk seeded onto it from the fixture records."""
    signer = Signer(Ed25519PrivateKey.generate(), tmp_path / "signer")
    store = LogStore(tmp_path / "desk", signer, FIXTURES / "records.yaml")
    yield {"signer": signer, "store": store, "tmp": tmp_path}
    store.close()
    signer.close()


def _same(a, b):
    assert a.size() == b.size() and a.head() == b.head() and a.root() == b.root()


def test_a_seeded_desk_holds_the_seed_as_link_zero_judged_by_the_signer(started):
    s, st = started["signer"], started["store"]
    _same(st.store, s.replica)
    assert st.revision() == 1 and st.store.size() == 1 and not st.verify_log()
    assert st.log(5)[-1]["action"] == "seed" and st.log(5)[-1]["link"] == 0


def test_one_desk_per_directory(started):
    with pytest.raises(StoreFault, match="one writer"):
        LogStore(started["tmp"] / "desk", started["signer"])


def test_a_restart_reaches_the_same_head_and_records(started):
    st = started["store"]
    Desk(st).propose(ANN, ADD)
    before = st.load()
    st.close()
    again = LogStore(started["tmp"] / "desk", started["signer"])
    try:
        _same(again.store, started["signer"].replica)
        assert again.load() == before and not again.verify_log()
    finally:
        again.close()
    started["store"] = LogStore(started["tmp"] / "desk", started["signer"])   # for the fixture's teardown


def test_a_desk_whose_replica_was_deleted_rebuilds_it_from_the_signer(started):
    st = started["store"]
    Desk(st).propose(ANN, ADD)
    before = st.load()
    st.close()
    for f in started["tmp"].glob("desk/log*.db*"):
        f.unlink()
    rebuilt = LogStore(started["tmp"] / "desk", started["signer"])
    try:
        _same(rebuilt.store, started["signer"].replica)
        assert rebuilt.load() == before
    finally:
        rebuilt.close()
    started["store"] = LogStore(started["tmp"] / "desk", started["signer"])


def test_a_resync_swaps_in_a_new_replica_and_a_restart_opens_it(started):
    st = started["store"]
    Desk(st).propose(ANN, ADD)
    before, old = st.load(), (started["tmp"] / "desk" / "log.db")
    st.resync()
    assert not old.exists() and (started["tmp"] / "desk" / "log.current").exists()
    _same(st.store, started["signer"].replica)
    assert st.load() == before
    st.close()
    started["store"] = LogStore(started["tmp"] / "desk", started["signer"])
    assert started["store"].load() == before


def test_ops_between_carry_exactly_the_change(started):
    st = started["store"]
    old = st.load()
    new = copy.deepcopy(old)
    new["memberships"] = new["memberships"][1:]                     # one record gone
    new["memberships"][0] = {**new["memberships"][0], "end": "2027-01-31T00:00:00Z"}
    ops, tokens = ops_between(old, new)
    assert {o["op"] for o in ops} == {"put", "del"} and all(o["kind"] == "memberships" for o in ops)
    assert len(ops) == 2 and tokens == [] and ops_between(old, old) == ([], [])


def test_a_refused_change_leaves_the_desk_where_it_was(started):
    st = started["store"]
    before, size = st.load(), st.store.size()
    bad = copy.deepcopy(before)
    bad["memberships"].append({**bad["memberships"][0], "membership_id": "M-example-9999", "group": "no-such-group"})
    with pytest.raises(SignerRefused, match="unknown group"):
        st.commit(bad, {"action": "add_member", "actor": "keyclerk:test", "outcome": "applied"})
    assert st.store.size() == size and st.load() == before


def test_a_change_whose_answer_was_lost_is_not_applied_twice(started):
    s, st = started["signer"], started["store"]
    doc = Desk(st)
    doc.propose(ANN, ADD)
    rec = st.load()
    rec["memberships"][0] = {**rec["memberships"][0], "end": "2027-02-01T00:00:00Z"}   # ends a month earlier
    ops, _ = ops_between(st.load(), rec)
    entry = {"change_id": "C-face01", "action": "extend", "actor": "keyclerk:test", "outcome": "applied"}
    s.propose(st.follower.base(), {"ops": ops, "entry": entry}, [])   # applied; the desk never heard
    size = s.replica.size()
    st._propose(ops, [], [], entry)                                     # the desk proposes it again
    assert s.replica.size() == size
    _same(st.store, s.replica)


def test_a_desk_follows_a_migrated_signer_and_takes_its_mapping(world, tmp_path):  # noqa: F811
    s = world["signer"]
    st = LogStore(tmp_path / "followed", s)
    try:
        _same(st.store, s.replica)
        assert dict(st.store.side_scan("anchor_map")) == dict(s.replica.side_scan("anchor_map"))
        assert st.load() == RP.records(s.replica)
    finally:
        st.close()


def test_a_desk_opens_on_a_frozen_signer_and_says_so(started):
    s, st = started["signer"], started["store"]
    st.close()
    s._freeze("a test freeze")
    frozen = LogStore(started["tmp"] / "desk", s)
    try:
        assert "a test freeze" in frozen.frozen and frozen.load()["realm"] == "example"
        doc = frozen.load()
        with pytest.raises(SignerRefused, match="a test freeze"):
            frozen.commit({**doc, "memberships": doc["memberships"][1:]}, {"action": "x", "outcome": "applied"})
    finally:
        started["store"] = frozen


def test_a_signer_without_a_log_needs_a_seed_or_a_migration(tmp_path):
    s = Signer(Ed25519PrivateKey.generate(), tmp_path / "signer")
    try:
        with pytest.raises(StoreFault, match="migrate its signed YAML revision"):
            LogStore(tmp_path / "desk", s)
    finally:
        s.close()
    shutil.rmtree(tmp_path / "desk", ignore_errors=True)


def test_the_log_store_is_a_desk_store_and_the_configuration_opens_it(started):
    from keyclerk.store import desk_store as DS
    assert isinstance(started["store"], DS.DeskStore)
    missing = [m for m in DS.DeskStore.__annotations__ | dict(vars(DS.DeskStore))
               if not m.startswith("_") and not hasattr(started["store"], m)]
    assert not missing
    other = DS.open_desk_store({"store": {"kind": "sqlite"}}, started["tmp"] / "other", None, signer=started["signer"])
    try:
        assert type(other).__name__ == "LogStore" and other.store.head() == started["signer"].replica.head()
    finally:
        other.close()
