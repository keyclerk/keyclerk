# SPDX-License-Identifier: EUPL-1.2
"""The HA change link (decision 0031 points 3 and 10, operator 2026-11-05): the ha head record is put or removed only by
a link the security officer and a root trust owner each confirmed, on one base; with HA on, a planned change is signed
on the commit witness's committed head, and a break-glass only while the commit witness is stopped, naming the one node
that signs on. A desk's change never touches the record."""
import pytest

from keyclerk import commit_witness as C
from keyclerk import ha as HA
from keyclerk.signer import Signer, SignerRefused
from keyclerk.store import link as L
from keyclerk.store import replay
from keyclerk.store.follow import Follower, NotCommitted
from keyclerk.store.memory import MemoryStore
from keyclerk.store import note as N
from tests.test_signer_ha import WKEY, Net, confirm, pair, verify  # noqa: F401 - the fixture
from tests.test_signer_replica import ADD, change_ops, world  # noqa: F401 - the fixture

CFG = {"origin": "keyclerk.example/ha-change", "commit_witness": N.vkey("witness.example/commit", N.COSIGNATURE,
                                                                       N.raw_public(WKEY)), "nodes": ["node-a", "node-b"]}


class _Current:
    def __init__(self, world):
        self.world = world

    def __getattr__(self, name):
        return getattr(self.world["signer"], name)


def _people(s):
    root = replay.records(s.replica)["root"]
    return root["officer"], root["holders"][0]["anchor"]


def _last(s):
    return L.open_link(s.replica.link(s.replica.size() - 1), s.public_key())[0]["change"]


def _offline(p, world):
    """Node a stopped and opened offline, as python -m keyclerk.ha does it; its commit witness client beside it."""
    p["a"].close()
    s = world["signer"] = Signer(world["key"], p["a"].state)
    return s, C.CommitClient("http://cw", transport=p["nets"]["a"])


def test_ha_is_switched_on_only_by_the_officer_and_a_root_trust_owner(world):  # noqa: F811
    s = world["signer"]
    officer, root = _people(s)
    for people, why in (((officer,), "a root trust owner"), ((root,), "the security officer")):
        with pytest.raises(SignerRefused, match=why):
            s.ha_change("set", CFG, None, confirm(s, "set", CFG, people=people), verify)
    other = {**CFG, "nodes": ["node-a", "node-c"]}
    with pytest.raises(SignerRefused, match="does not hold"):            # proofs of another configuration
        s.ha_change("set", CFG, None, confirm(s, "set", other), verify)
    assert s.replica.get("head", "ha") is None
    out = s.ha_change("set", CFG, None, confirm(s, "set", CFG), verify)
    ch = _last(s)
    assert ch["entry"]["action"] == "ha_set" and ch["ha"]["mode"] == "set"
    assert sorted(c["by"] for c in ch["ha"]["confirmations"]) == sorted((officer, root))
    assert replay.records(s.replica)["ha"] == CFG and out["revision"] == replay.revision(s.replica)
    fresh = lambda: MemoryStore(s.public_key(), "example")   # noqa: E731
    f = Follower(fresh(), _Current(world), fresh)
    with pytest.raises(NotCommitted):                             # it checks and adopts the HA change link, then
        f.catch_up()                                              # waits for the commit witness's countersignature
    assert f.store.head() == s.replica.head() and replay.records(f.store)["ha"] == CFG and not f.alarms
    with pytest.raises(SignerRefused, match="already holds"):
        s.ha_change("set", CFG, None, confirm(s, "set", CFG), verify)


def test_a_proof_stands_for_one_base(world, tmp_path):  # noqa: F811
    s = world["signer"]
    proofs = confirm(s, "set", CFG)
    s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},
              {"ops": change_ops(tmp_path, ADD, world), "entry": {"change_id": "C-a0move"}}, [])
    with pytest.raises(SignerRefused, match="does not hold"):            # the head moved: the statement is another
        s.ha_change("set", CFG, None, proofs, verify)


@pytest.mark.parametrize("op", [{"op": "put", "kind": "head", "key": "ha", "record": {"value": CFG}},
                                {"op": "del", "kind": "head", "key": "ha"}])
def test_a_desk_change_never_touches_the_ha_record(world, op):  # noqa: F811
    s = world["signer"]
    with pytest.raises(SignerRefused, match="only by an HA change link"):
        s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},
                  {"ops": [op], "entry": {"change_id": "C-a0desk"}}, [])


def _body(ops, ha, seq=3):
    return L.link_body("example", seq, "0" * 64, 1, "2026-11-05T12:00:00Z", ops, {"change_id": "C-a0b1c2"}, ha=ha)


TWO = [{"by": "a", "proof": "0" * 64}, {"by": "b", "proof": "1" * 64}]
PUT = {"op": "put", "kind": "head", "key": "ha", "record": {"value": CFG}}
DEL = {"op": "del", "kind": "head", "key": "ha"}


@pytest.mark.parametrize("ops,ha,seq,why", [
    ([DEL], {"mode": "set", "confirmations": TWO}, 3, "one op: put head ha"),
    ([PUT], {"mode": "off", "confirmations": TWO}, 3, "one op: del head ha"),
    ([], {"mode": "off", "confirmations": TWO}, 3, "one op"),
    ([DEL, {"op": "del", "kind": "groups", "key": "g"}], {"mode": "off", "confirmations": TWO}, 3, "one op"),
    ([DEL], {"mode": "break_glass", "confirmations": TWO}, 3, "node"),
    ([DEL], {"mode": "off", "confirmations": TWO, "node": "node-a"}, 3, "node"),
    ([DEL], {"mode": "off", "confirmations": TWO[:1]}, 3, "two"),
    ([DEL], {"mode": "off", "confirmations": [TWO[0], TWO[0]]}, 3, "two different"),
    ([DEL], {"mode": "promote", "confirmations": TWO}, 3, "set, off or break_glass"),
    ([PUT], {"mode": "set", "confirmations": TWO}, 0, "follows the genesis"),
])
def test_the_link_format_holds_an_ha_change_to_its_one_op(ops, ha, seq, why):
    with pytest.raises(L.StoreRefused, match=why):
        _body(ops, ha, seq)


def test_with_ha_on_a_planned_change_is_signed_only_on_the_committed_head(pair, world, tmp_path):  # noqa: F811
    s, cw = _offline(pair, world)
    cfg = replay.records(s.replica)["ha"]
    with pytest.raises(SignerRefused, match="give the commit witness"):
        s.ha_change("off", None, None, confirm(s, "off", None), verify)
    pair["nets"]["a"].down = True
    with pytest.raises(SignerRefused, match="break"):                    # witness lost: the planned way is closed
        s.ha_change("off", None, None, confirm(s, "off", None), verify, cw)
    pair["nets"]["a"].down = False
    s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},   # a head the witness never took
              {"ops": change_ops(tmp_path, ADD, world), "entry": {"change_id": "C-a0tail"}}, [])
    with pytest.raises(SignerRefused, match="not the committed head"):
        s.ha_change("off", None, None, confirm(s, "off", None), verify, cw)
    assert replay.records(s.replica)["ha"] == cfg


def test_ha_is_switched_off_on_the_committed_head(pair, world):  # noqa: F811
    s, cw = _offline(pair, world)
    s.ha_change("off", None, None, confirm(s, "off", None), verify, cw)
    assert s.replica.get("head", "ha") is None and _last(s)["entry"]["action"] == "ha_off"


def test_break_glass_only_while_the_commit_witness_is_stopped_naming_one_node(pair, world, tmp_path):  # noqa: F811
    s, cw = _offline(pair, world)
    with pytest.raises(SignerRefused, match="stop it"):
        s.ha_change("break_glass", None, "node-a", confirm(s, "break_glass", None, "node-a"), verify, cw)
    pair["nets"]["a"].down = True                                     # the commit witness stopped (point 10)
    with pytest.raises(SignerRefused, match="not one of the log's HA nodes"):
        s.ha_change("break_glass", None, "node-z", confirm(s, "break_glass", None, "node-z"), verify, cw)
    with pytest.raises(SignerRefused, match="names the one signer node"):
        s.ha_change("break_glass", None, None, confirm(s, "break_glass", None), verify, cw)
    with pytest.raises(SignerRefused, match="does not hold"):           # proofs naming another node
        s.ha_change("break_glass", None, "node-a", confirm(s, "break_glass", None, "node-b"), verify, cw)
    base = s.replica.size()
    s.ha_change("break_glass", None, "node-a", confirm(s, "break_glass", None, "node-a"), verify, cw)
    ch = _last(s)
    assert ch["entry"]["action"] == "ha_break_glass" and ch["ha"]["node"] == "node-a"
    assert s.replica.get("head", "ha") is None and s.replica.size() == base + 1
    s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},   # it signs on, unwitnessed, from the base
              {"ops": change_ops(tmp_path, ADD, world), "entry": {"change_id": "C-a0after"}}, [])
    new = {**CFG, "origin": "keyclerk.example/ha-again"}              # HA back: a commit witness seeded from its head
    s.ha_change("set", new, None, confirm(s, "set", new), verify)
    assert replay.records(s.replica)["ha"] == new


def test_the_statement_names_mode_base_and_node(world):  # noqa: F811
    s = world["signer"]
    officer, _ = _people(s)
    size, head = s.replica.size(), s.replica.head().hex()
    seen = {HA.statement("example", officer, "off", size, head, None, None),
            HA.statement("example", officer, "break_glass", size, head, None, "node-a"),
            HA.statement("example", officer, "break_glass", size, head, None, "node-b"),
            HA.statement("example", officer, "off", size + 1, head, None, None),
            HA.statement("example", officer, "set", size, head, CFG, None),
            HA.statement("other", officer, "off", size, head, None, None)}
    assert len(seen) == 6
