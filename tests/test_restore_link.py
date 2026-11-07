# SPDX-License-Identifier: EUPL-1.2
"""The restore link (decision 0019 point 5, issue 27): when no follower holds the links a restored signer lost, it
appends one link with no ops that resumes the numbering above the confirmed mark, so no revision number is signed
twice; followers replaying the chain reach the same revision."""
import json
import shutil

import pytest
from tests.test_signer_replica import ADD, change_ops, world  # noqa: F401 - fixture

from keyclerk import restore
from keyclerk.signer import Signer, SignerRefused
from keyclerk.store import link as L
from keyclerk.store import replay
from keyclerk.store.follow import Follower
from keyclerk.store.memory import MemoryStore

@pytest.fixture(autouse=True)
def _trustees_pinned(monkeypatch):
    """A restore link needs a pinned trustee set (0.29 review N8); these tests are not about trustee signatures."""
    from keyclerk import trustees as T
    from tests.test_trustees import pinned_set
    ts = pinned_set("example")
    monkeypatch.setattr(T, "pinned", lambda: {"set": ts, "since": 10 ** 9})



def _people(signer):
    root = replay.records(signer.replica)["root"]
    return root["officer"], root["holders"][0]["anchor"]


def _tokens(signer, mark, *people):
    head = signer.replica.head().hex()
    return [(by, json.dumps({"nonce": restore.statement("example", by, mark, head), "by": by})) for by in people]


def verify(token, nonce, by):
    t = json.loads(token)
    if t["nonce"] != nonce or t["by"] != by:
        raise ValueError("this proof is for another statement")


class _Current:
    def __init__(self, world):
        self.world = world

    def __getattr__(self, name):
        return getattr(self.world["signer"], name)


def _restored_without_followers(world, tmp_path):
    """The signer signs one more change after its backup; then the backup comes back and nobody holds that link."""
    s = world["signer"]
    s.close()
    shutil.copytree(s.state, tmp_path / "backup")
    s = world["signer"] = Signer(world["key"], s.state)
    out = s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},
                    {"ops": change_ops(tmp_path, ADD, world), "entry": {"change_id": "C-a0lost"}}, [])
    lost = out["revision"]
    s.close()
    shutil.rmtree(s.state)
    shutil.copytree(tmp_path / "backup", s.state)
    s = world["signer"] = Signer(world["key"], s.state)
    return s, lost


def test_a_restore_link_resumes_above_the_mark_and_followers_agree(world, tmp_path):
    s, lost = _restored_without_followers(world, tmp_path)
    assert replay.revision(s.replica) == lost - 1                 # the restored chain stops before the lost revision
    officer, root = _people(s)
    out = s.restore_link(lost, _tokens(s, lost, officer, root), verify)
    assert out["revision"] == lost + 1                            # the lost number is never signed again
    nxt = s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},
                    {"ops": change_ops(tmp_path, {**ADD, "anchor": "idp:44aa-dirk"}, world),
                     "entry": {"change_id": "C-a0next"}}, [])
    assert nxt["revision"] == lost + 2
    fresh = lambda: MemoryStore(s.public_key(), "example")   # noqa: E731
    f = Follower(fresh(), _Current(world), fresh)
    f.catch_up()                                                  # a follower replays the whole chain from scratch
    assert f.store.head() == s.replica.head() and replay.revision(f.store) == lost + 2 and not f.alarms
    s.close()
    world["signer"] = Signer(world["key"], s.state)               # a restart reads the same numbering back
    assert replay.revision(world["signer"].replica) == lost + 2


@pytest.mark.parametrize("who, why", [("officer", "root trust owner"), ("root", "security officer")])
def test_a_restore_link_needs_the_officer_and_a_root_trust_owner(world, tmp_path, who, why):
    s, lost = _restored_without_followers(world, tmp_path)
    officer, root = _people(s)
    size = s.replica.size()
    with pytest.raises(SignerRefused, match=why):
        s.restore_link(lost, _tokens(s, lost, officer if who == "officer" else root), verify)
    assert s.replica.size() == size                               # nothing was signed


def test_a_restore_link_never_lowers_the_revision(world, tmp_path):
    s, lost = _restored_without_followers(world, tmp_path)
    for i, who in enumerate(("idp:44aa-dirk", "idp:55bb-eva")):    # a restored chain a few revisions long
        s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},
                  {"ops": change_ops(tmp_path, {**ADD, "anchor": who}, world), "entry": {"change_id": f"C-a0b{i}"}}, [])
    officer, root = _people(s)
    below = replay.revision(s.replica) - 1
    assert below >= 1
    with pytest.raises(SignerRefused, match="below revision"):
        s.restore_link(below, _tokens(s, below, officer, root), verify)


@pytest.mark.parametrize("restore_part", [
    {"mark": 5, "confirmations": [{"by": "a", "proof": "0" * 64}]},                                   # one person
    {"mark": 5, "confirmations": [{"by": "a", "proof": "0" * 64}, {"by": "a", "proof": "1" * 64}]},   # the same twice
    {"mark": 0, "confirmations": [{"by": "a", "proof": "0" * 64}, {"by": "b", "proof": "1" * 64}]},   # no mark
    {"mark": 5, "confirmations": [{"by": "a", "proof": "xyz"}, {"by": "b", "proof": "1" * 64}]},      # not a hash
])
def test_a_malformed_restore_part_is_refused(restore_part):
    with pytest.raises(L.StoreRefused, match="restore"):
        L.link_body("example", 3, "0" * 64, 1, "2026-11-03T12:00:00Z", [], {"change_id": "C-a0b1c2"},
                    restore=restore_part)


def test_a_restore_link_carries_no_ops():
    op = {"op": "put", "kind": "groups", "key": "x", "record": {"group_id": "x"}}
    with pytest.raises(L.StoreRefused, match="no ops"):
        L.link_body("example", 3, "0" * 64, 1, "2026-11-03T12:00:00Z", [op], {"change_id": "C-a0b1c2"},
                    restore={"mark": 5, "confirmations": [{"by": "a", "proof": "0" * 64}, {"by": "b", "proof": "1" * 64}]})
