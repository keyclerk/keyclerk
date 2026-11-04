# SPDX-License-Identifier: EUPL-1.2
"""Restoring the change log's signer (decision 0019 point 5, issue 27): revision numbers are positions in a signed
chain, so a signer restored from an older backup takes its lost links back from a follower whose chain verifies and
starts with the restored one; it never signs at a lost position, and a follower that forked is refused."""
import shutil

import pytest
from tests.test_signer_replica import ADD, change_ops, world  # noqa: F401 - fixture

from keyclerk import restore
from keyclerk.signer import Signer
from keyclerk.store.follow import Follower
from keyclerk.store.memory import MemoryStore


class _Current:
    def __init__(self, world):
        self.world = world

    def __getattr__(self, name):
        return getattr(self.world["signer"], name)


def _lost_one_link(world, tmp_path):
    """A follower holds a link the signer signed after its backup; then the signer's state is restored from it."""
    s = world["signer"]
    fresh = lambda: MemoryStore(s.public_key(), "example")   # noqa: E731
    f = Follower(fresh(), _Current(world), fresh)
    f.catch_up()
    s.close()
    shutil.copytree(s.state, tmp_path / "backup")
    s = world["signer"] = Signer(world["key"], s.state)
    s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},
              {"ops": change_ops(tmp_path, ADD, world), "entry": {"change_id": "C-a0lost"}}, [])
    f.catch_up()
    lost_head = f.store.head()
    s.close()
    shutil.rmtree(s.state)
    shutil.copytree(tmp_path / "backup", s.state)                # the disk is lost; the backup comes back
    return f, lost_head


def test_the_signer_takes_its_lost_links_back_from_a_follower(world, tmp_path):
    f, lost_head = _lost_one_link(world, tmp_path)
    pub = world["signer"].public_key()
    out = restore.recover_log(world["signer"].state, f.store, pub)
    assert out["recovered"] == 1
    s = world["signer"] = Signer(world["key"], world["signer"].state)
    assert not s.broken and s.replica.head() == lost_head       # the same history, no fork
    s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},
              {"ops": change_ops(tmp_path, {**ADD, "anchor": "idp:44aa-dirk"}, world),
               "entry": {"change_id": "C-a0next"}}, [])
    assert s.replica.size() == f.store.size() + 1                # the next link lands after the recovered one


def test_a_follower_that_forked_from_the_restored_chain_is_refused(world, tmp_path):
    f, _ = _lost_one_link(world, tmp_path)
    s = world["signer"] = Signer(world["key"], world["signer"].state)
    s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},     # signed at the lost position: a fork
              {"ops": change_ops(tmp_path, {**ADD, "anchor": "idp:44aa-dirk"}, world),
               "entry": {"change_id": "C-a0fork"}}, [])
    size = s.replica.size()
    s.close()
    with pytest.raises(restore.RestoreMode, match="differs from the restored one"):
        restore.recover_log(s.state, f.store, s.public_key())
    world["signer"] = Signer(world["key"], s.state)
    assert world["signer"].replica.size() == size                # nothing was changed


def test_a_follower_with_nothing_newer_changes_nothing(world, tmp_path):
    s = world["signer"]
    fresh = lambda: MemoryStore(s.public_key(), "example")   # noqa: E731
    f = Follower(fresh(), _Current(world), fresh)
    f.catch_up()
    s.close()
    assert restore.recover_log(s.state, f.store, s.public_key())["recovered"] == 0
    world["signer"] = Signer(world["key"], s.state)
