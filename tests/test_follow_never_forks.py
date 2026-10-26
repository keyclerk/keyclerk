# SPDX-License-Identifier: EUPL-1.2
"""A follower swaps in a resynced log only when it extends the history it verified (decision 0022)."""
import shutil

from tests.test_signer_replica import ADD, TOKEN, _ann, change_ops, world  # noqa: F401 - fixture

from keyclerk.signer import Signer
from keyclerk.store import link as L
from keyclerk.store.follow import Follower
from keyclerk.store.memory import MemoryStore


class _Current:
    """The address of 'the signer', whichever process answers there."""
    def __init__(self, world):
        self.world = world

    def __getattr__(self, name):
        return getattr(self.world["signer"], name)


def test_a_follower_never_swaps_its_verified_history_for_a_shorter_or_forked_one(world, tmp_path):
    s = world["signer"]
    client = _Current(world)
    fresh = lambda: MemoryStore(s.public_key(), "example")   # noqa: E731
    f = Follower(fresh(), client, fresh)
    f.catch_up()

    s.close()                                                    # an ordinary whole-state backup
    shutil.copytree(s.state, tmp_path / "backup")
    s = world["signer"] = Signer(world["key"], s.state)
    s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},
              {"ops": change_ops(tmp_path, ADD, world), "entry": {"change_id": "C-a5real"}}, [])
    f.catch_up()
    n = f.store.size() - 1
    held = f.store.link(n)                                       # the follower verified link n: the real change

    s.close()                                                    # the backup restored whole, as the refusal advises
    shutil.rmtree(s.state)
    shutil.copytree(tmp_path / "backup", s.state)
    s = world["signer"] = Signer(world["key"], s.state)
    assert not s.broken                                          # the signer itself accepts the older state
    proof = L.proof_record({"records": ["M-example-0001"], "by": _ann(s), "token": TOKEN})
    other = [{"op": "put", "kind": "approval_proofs", "key": proof["sha256"], "record": proof}]
    s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},
              {"ops": other, "entry": {"change_id": "C-a5fork"}}, [[proof["sha256"], TOKEN]])
    assert s.replica.size() == n + 1 and s.replica.link(n) != held   # two signed links n: equivocation

    try:
        f.catch_up()
    except Exception:   # noqa: BLE001 - refusing loudly is fine
        pass
    assert f.store.link(n) == held, "the follower replaced history it had verified with the signer's fork"
