# SPDX-License-Identifier: EUPL-1.2
"""Decision 0031 point 6, the desk's own check: in HA mode a desk's store adopts a size only with the commit witness's
countersignature on it, both signatures checked by the desk. A signer node that serves links it never committed, or a
checkpoint only its records key signed, or an answer with no countersignature, moves the desk nowhere."""
import pytest

from keyclerk.signer import SignerRefused
from keyclerk.store import note as N
from keyclerk.store.follow import Follower, NotCommitted
from keyclerk.store.link import StoreRefused
from keyclerk.store.memory import MemoryStore
from tests.test_signer_ha import ORIGIN, WKEY, _add, _wait, pair, _trustees_pinned  # noqa: F401 - the fixture
from tests.test_signer_replica import world  # noqa: F401 - the fixture


class Lying:
    """A signer node as a desk sees it, with what it serves bent: its whole replica, no countersignature, or a
    checkpoint the records key alone signed."""

    def __init__(self, s, links="committed", commit="real"):
        self.s, self.mode, self.commit = s, links, commit

    def __getattr__(self, name):
        return getattr(self.s, name)

    def head(self):
        h = dict(self.s.head())
        if self.commit == "none":
            h["commit"] = None
        elif self.commit == "records_key_only":
            r = self.s.replica
            text = N.checkpoint_text(ORIGIN, r.size(), r.root())
            h["commit"] = text + "\n" + N.sign(text, ORIGIN, self.s.key)
        elif self.commit == "another_root":           # both keys signed it, over a root these links do not reach
            text = N.checkpoint_text(ORIGIN, self.s.replica.size(), b"\x07" * 32)
            h["commit"] = (text + "\n" + N.sign(text, ORIGIN, self.s.key)
                           + N.cosign(text, "witness.example/commit", WKEY, 1_800_000_000))
        return h

    def links(self, start, limit):
        if self.mode == "committed":
            return self.s.links(start, limit)
        r = self.s.replica                        # everything it holds, the uncommitted tail too, whatever was asked
        return {"links": list(r.links(start, r.size())), "size": r.size()}

    def propose(self, base, change, tokens):
        out = dict(self.s.propose(base, change, tokens))
        if self.commit != "real":
            out.pop("commit", None)
        return out


def _desk(a, client):
    fresh = lambda: MemoryStore(a.public_key(), "example")   # noqa: E731
    f = Follower(fresh(), client, fresh, from_snapshot=False)
    f.catch_up()
    return f


def test_a_desk_adopts_only_what_the_commit_witness_countersigned(pair):
    a = pair["a"]
    assert _wait(pair, a) == "active"
    f = _desk(a, Lying(a, links="all"))
    assert f.store.size() == a.ha["committed"] == a.replica.size() and not f.alarms
    _add(pair, a)                                         # committed; the desk is one behind
    pair["nets"]["a"].drop_commit = True                  # a signs a link the witness never takes
    with pytest.raises(SignerRefused, match="unknown"):
        _add(pair, a)
    assert a.replica.size() == a.ha["committed"] + 1
    f.catch_up()                                          # the node serves its tail; the desk stops at the commit
    assert f.store.size() == a.ha["committed"] and not f.alarms


def test_a_desk_adopts_nothing_without_a_countersignature(pair):
    a = pair["a"]
    assert _wait(pair, a) == "active"
    f = _desk(a, a)
    _add(pair, a)
    f.client = Lying(a, commit="none")
    with pytest.raises(NotCommitted, match="no countersignature"):
        f.catch_up()
    assert f.store.size() == a.replica.size() - 1


def test_a_checkpoint_the_records_key_alone_signed_is_refused(pair):
    a = pair["a"]
    assert _wait(pair, a) == "active"
    f = _desk(a, a)
    _add(pair, a)
    size = f.store.size()
    f.client = Lying(a, commit="records_key_only")
    with pytest.raises(StoreRefused, match="not countersigned by the log's commit witness"):
        f.catch_up()
    assert f.store.size() == size and f.alarms


def test_an_answer_without_a_countersignature_is_not_applied(pair, tmp_path):
    from tests.test_signer_replica import ADD, change_ops
    a = pair["a"]
    assert _wait(pair, a) == "active"
    f = _desk(a, a)
    f.client = Lying(a, commit="none")
    size = f.store.size()
    with pytest.raises(NotCommitted):                     # the answer is not applied; catching up shows no commit
        f.propose({"ops": change_ops(tmp_path, ADD, {"signer": a}), "entry": {"change_id": "C-a0nocw"}})
    assert f.store.size() == size and a.replica.size() == size + 1
    f.client = a
    f.catch_up()                                          # with the countersignature, the same link is adopted
    assert f.store.size() == size + 1 and f.store.head() == a.replica.head()


def test_links_that_reach_another_root_than_the_countersigned_one_are_refused(pair):
    a = pair["a"]
    assert _wait(pair, a) == "active"
    f = _desk(a, a)
    _add(pair, a)
    size = f.store.size()
    f.client = Lying(a, commit="another_root")
    with pytest.raises(StoreRefused, match="another root"):
        f.catch_up()
    assert f.alarms and f.store.size() in (size, size + 1)
