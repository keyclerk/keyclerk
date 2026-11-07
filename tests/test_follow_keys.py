# SPDX-License-Identifier: EUPL-1.2
"""A follower moves to newer records-key histories only on the pinned trustees' word (#41): a planned rotation is
adopted in place; a recovery drops what the stolen key signed after the trusted checkpoint and resyncs from there."""
import pytest

from keyclerk import records_keys as K
from keyclerk import trustees as T
from keyclerk.store import link as L
from keyclerk.store.follow import Follower
from keyclerk.store.memory import MemoryStore
from tests.test_records_keys import K1, K2, K3, REALM, TS, V1, WVKEY, body, hx, note, seal, v2_body

ENTRY = {"change_id": "C-t1", "action": "t", "outcome": "applied", "actor": None, "records": {}}


def _root_after(keys):
    """The log's root after links signed by these keys, as the Signer below writes them (deterministic)."""
    s = Signer(K.KeyHistory(V1))
    h = K.KeyHistory(V1)
    for i, k in enumerate(keys):
        if k is K2 and isinstance(s.log.pinned, K.KeyHistory) and s.log.pinned.version == 1:
            h = K.advance(h, seal(v2_body(b=i, root=s.log.root()), K2), TS, WVKEY)
            s.log.adopt_history(h)
        s.sign(k)
    return s.log.root()


class Signer:
    """The signer as the follower sees it: its own log, signed by the key in force, and the histories it holds."""

    def __init__(self, history):
        self.log = MemoryStore(history, REALM)
        self.versions = []

    def sign(self, key, n=1):
        for _ in range(n):
            head = self.log.head()
            b = L.link_body(REALM, self.log.size(), head.hex() if head else L.ZERO, 1, "2026-11-06T22:00:00Z", [], ENTRY)
            self.log.append(L.seal_body(key, b))
        self._key = key

    def links(self, start, limit):
        return {"links": [self.log.link(i) for i in range(start, min(self.log.size(), start + limit))],
                "size": self.log.size()}

    def checkpoint(self, _):
        return {"checkpoint": L.seal_checkpoint(self._key, REALM, self.log.size(), self.log.root(), self.log.head(), 1,
                                                "2026-11-06T22:00:00Z")}

    def head(self):
        h = self.log.head()
        return {"size": self.log.size(), "head": h.hex() if h else L.ZERO, "root": self.log.root().hex()}

    def tokens(self, after, n):
        return {"tokens": []}

    def records_keys(self):
        return {"versions": self.versions}


@pytest.fixture
def pinned(monkeypatch):
    monkeypatch.setattr(T, "pinned", lambda: {"set": TS, "since": 0})


def follower(history):
    return Follower(MemoryStore(history, REALM), None, lambda: MemoryStore(hx(K1), REALM), from_snapshot=False)


def test_a_planned_rotation_is_adopted_in_place(pinned):
    h1 = K.KeyHistory(V1)
    s = Signer(h1)
    s.sign(K1, 2)
    f = follower(h1)
    f.client = s
    f.catch_up()
    v2 = seal(v2_body(b=2, root=_root_after([K1, K1])), K2)
    s.log.adopt_history(K.advance(h1, v2, TS, WVKEY))
    s.versions = [v2]
    s.sign(K2, 2)
    assert f.follow_keys() == 2
    f.catch_up()
    assert f.store.size() == 4 and not f.alarms


def test_without_a_pinned_trustee_set_nothing_is_adopted(monkeypatch):
    monkeypatch.setattr(T, "pinned", lambda: None)
    h1 = K.KeyHistory(V1)
    s = Signer(h1)
    s.versions = [seal(v2_body(b=2, root=_root_after([K1, K1])), K2)]
    f = follower(h1)
    f.client = s
    assert f.follow_keys() == 1 and "pins no trustee set" in f.alarms[-1]


def test_a_forged_history_raises_an_alarm_and_is_not_adopted(pinned):
    h1 = K.KeyHistory(V1)
    s = Signer(h1)
    forged = seal(v2_body(b=2, root=_root_after([K1, K1])), K2, who=("eva", "ingrid"))          # two officers: no root trust owner
    s.versions = [forged]
    f = follower(h1)
    f.client = s
    assert f.follow_keys() == 1 and "does not hold" in f.alarms[-1]


def test_a_recovery_drops_what_the_stolen_key_signed_and_resyncs_from_the_switch(pinned):
    h1 = K.KeyHistory(V1)
    v2 = seal(v2_body(b=2, root=_root_after([K1, K1])), K2)
    h2 = K.advance(h1, v2, TS, WVKEY)
    stolen = Signer(h1)
    stolen.sign(K1, 2)
    stolen.log.adopt_history(h2)
    stolen.sign(K2, 4)                                                 # links 2..5; K2 is stolen after link 3
    f = follower(h1)
    f.client = stolen
    stolen.versions = [v2]
    f.follow_keys()
    f.catch_up()
    assert f.store.size() == 6
    keys = [h2.doc["keys"][0], {**h2.doc["keys"][1], "to_seq": 4},
            {"key": hx(K3), "origin": "keyclerk.example/log-3", "from_seq": 4, "to_seq": None}]
    v3 = seal(body(3, keys, {"note": note("keyclerk.example/log-2", 4, K2, root=_root_after([K1, K1, K2, K2])),
                             "witness": WVKEY}), K3)
    recovered = Signer(h1)                                             # the signer restored to the trusted checkpoint
    recovered.sign(K1, 2)
    recovered.log.adopt_history(h2)
    for i in range(2, 4):
        recovered.log.append(stolen.log.link(i))
    recovered.log.adopt_history(K.advance(h2, v3, TS, WVKEY))
    recovered.sign(K3, 1)
    recovered.versions = [v2, v3]
    f.client = recovered
    assert f.follow_keys() == 3
    assert f.store.size() == 5 and f.store.link(4) == recovered.log.link(4)
    assert any("kept as evidence" in a for a in f.alarms)


def test_an_ordinary_resync_after_a_rotation_keeps_the_history(pinned):
    """A resync for any other reason (a divergence alarm) starts a fresh store with the genesis key only; it must take
    the history the old store held, or the new key's links would be refused."""
    h1 = K.KeyHistory(V1)
    s = Signer(h1)
    s.sign(K1, 2)
    v2 = seal(v2_body(b=2, root=_root_after([K1, K1])), K2)
    s.log.adopt_history(K.advance(h1, v2, TS, WVKEY))
    s.sign(K2, 2)
    s.versions = [v2]
    f = follower(h1)
    f.client = s
    f.follow_keys()
    f.catch_up()
    f.resync()
    assert f.store.size() == 4 and f.store.pinned.version == 2


def test_n10_a_forged_version_offered_first_does_not_block_the_valid_one(pinned):
    """0.29 review N10: the follower noted a version that does not hold and stopped, so a valid one offered after it
    was never taken; and a version offered before its predecessor waited for the next round."""
    h1 = K.KeyHistory(V1)
    s = Signer(h1)
    s.sign(K1, 2)
    f = follower(h1)
    f.client = s
    f.catch_up()
    forged = seal(v2_body(b=2, root=_root_after([K1, K1])), K2, who=("eva", "ingrid"))
    v2 = seal(v2_body(b=2, root=_root_after([K1, K1])), K2)
    s.log.adopt_history(K.advance(h1, v2, TS, WVKEY))
    s.versions = [forged, v2]
    assert f.follow_keys() == 2 and "does not hold" in f.alarms[-1]


def test_f8_the_revision_at_a_size_is_the_logs_own_count():
    from keyclerk.store import replay
    s = Signer(K.KeyHistory(V1))
    s.sign(K1, 3)
    assert replay.revision_at(s.log, s.log.size()) == replay.revision(s.log)
    assert replay.revision_at(s.log, 2) == replay.revision(s.log) - 1 and replay.revision_at(s.log, 0) is None
