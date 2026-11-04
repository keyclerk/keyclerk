# SPDX-License-Identifier: EUPL-1.2
"""Issue 28: the signer takes signed snapshots; a follower starts from one and refuses one that is not the signer's
log (decision 0022 point 1)."""
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.test_signer_replica import ADD, change_ops, world  # noqa: F401 - fixture

from keyclerk import edge as E
from keyclerk.store import link as L
from keyclerk.store import replay as RP
from keyclerk.store import snapshot as S
from keyclerk.store.follow import Follower
from keyclerk.store.link import StoreRefused
from keyclerk.store.memory import MemoryStore

pytestmark = pytest.mark.filterwarnings("ignore::ResourceWarning")


def _change(world, tmp_path, cid):
    s = world["signer"]
    s.propose({"size": s.replica.size(), "head": s.replica.head().hex()},
              {"ops": change_ops(tmp_path, ADD, world), "entry": {"change_id": cid}}, [])


def _follower(world):
    s = world["signer"]
    fresh = lambda: MemoryStore(s.public_key(), "example")   # noqa: E731
    return Follower(fresh(), s, fresh)


def test_the_signer_takes_a_snapshot_and_a_follower_starts_from_it(world, tmp_path):
    s = world["signer"]
    _change(world, tmp_path, "C-snap1")
    path = s.take_snapshot()
    assert path is not None and path.name == f"{s.replica.size()}.snapshot.json"
    assert s.take_snapshot() is None                                   # no new link: no new snapshot
    _change(world, tmp_path, "C-snap2")                                # the log moves on after the snapshot
    f = _follower(world)
    f.resync(snapshot=(S.read_sealed(path), path.with_name(path.name.replace("snapshot.json", "state.jsonl"))))
    assert f.store.size() == s.replica.size() and f.store.head() == s.replica.head()
    assert RP.records(f.store) == RP.records(s.replica)
    assert not f.alarms


def test_a_follower_refuses_a_snapshot_that_is_not_the_signers_log(world, tmp_path):
    s = world["signer"]
    _change(world, tmp_path, "C-snap3")
    path = s.take_snapshot()
    state = path.with_name(path.name.replace("snapshot.json", "state.jsonl"))
    sealed = S.read_sealed(path)
    body = E._parse(E._raw(sealed["bytes"]))
    forged = L._seal(Ed25519PrivateKey.generate(), S.FORMAT, body)          # not the records key
    with pytest.raises(StoreRefused, match="not signed by the records key"):
        _follower(world).resync(snapshot=(forged, state))
    other = L._seal(world["key"], S.FORMAT, {**body, "head": "ab" * 32})     # the records key, another head
    with pytest.raises(StoreRefused, match="head or root is not the log's"):
        _follower(world).resync(snapshot=(other, state))


def test_no_snapshot_before_a_passing_full_check_and_two_are_kept(world, tmp_path):
    s = world["signer"]
    last = s.last_check
    s.last_check = None
    assert s.take_snapshot() is None                                   # nothing checked yet since this start
    s.last_check = last
    for i in range(3):
        _change(world, tmp_path, f"C-keep{i}")
        assert s.take_snapshot() is not None
    kept = sorted(p.name for p in (s.state / "snapshots").iterdir())
    assert len(kept) == 4 and all(p.endswith((".snapshot.json", ".state.jsonl")) for p in kept)


def test_a_follower_fetches_the_signers_snapshot_over_the_protocol(world, tmp_path):
    s = world["signer"]
    _change(world, tmp_path, "C-fetch1")
    assert s.take_snapshot() is not None
    _change(world, tmp_path, "C-fetch2")
    s.STATE_CHUNK = 64                                                 # several pieces, as a large state would be
    seen = []
    real = s.snapshot_state

    def spy(size, offset, limit):
        seen.append(offset)
        return real(size, offset, min(limit, 64))
    s.snapshot_state = spy
    f = _follower(world)
    f.resync()                                                          # no snapshot given: it fetches the signer's
    assert len(seen) > 2 and f.store.size() == s.replica.size() and f.store.head() == s.replica.head()
    assert RP.records(f.store) == RP.records(s.replica) and not f.alarms


def test_without_a_snapshot_a_resync_replays_from_the_genesis(world, tmp_path):
    s = world["signer"]
    _change(world, tmp_path, "C-nosnap")
    assert s.snapshot() == {"snapshot": None}
    f = _follower(world)
    f.resync()
    assert f.store.head() == s.replica.head()


def test_a_fetched_state_that_was_changed_on_the_way_is_refused(world, tmp_path):
    import base64
    s = world["signer"]
    _change(world, tmp_path, "C-tamper")
    s.take_snapshot()
    real = s.snapshot_state

    def tampered(size, offset, limit):
        part = real(size, offset, limit)
        raw = base64.b64decode(part["chunk"]).replace(b"office-staff", b"office-stuff", 1)
        return {**part, "chunk": base64.b64encode(raw).decode()}
    s.snapshot_state = tampered
    with pytest.raises(StoreRefused):
        _follower(world).resync()
