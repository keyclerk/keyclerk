# SPDX-License-Identifier: EUPL-1.2
"""The records-key history (#41): versions signed by the trustees, windows that only ever clip at a switch, the new key
proving possession, and the switch resting on a checkpoint the old key signed and a witness countersigned."""
import base64
import copy
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from keyclerk import records_keys as K
from keyclerk.store import note as N
from tests.test_trustees import pinned_set, trustee_sigs

REALM = "example"
K1, K2, K3, MALLORY = (Ed25519PrivateKey.generate() for _ in range(4))
WITNESS = Ed25519PrivateKey.generate()
WNAME = "witness.example"
WVKEY = N.vkey(WNAME, N.COSIGNATURE, N.raw_public(WITNESS))
TS = pinned_set(REALM)
ROOT = hashlib.sha256(b"root").digest()


def hx(k):
    return E.public_hex(k)


def note(origin: str, size: int, key, witness=WITNESS, root=ROOT):
    text = N.checkpoint_text(origin, size, root)
    return text + "\n" + N.sign(text, origin, key) + (N.cosign(text, WNAME, witness, 1_793_000_000) if witness else "")


V1 = {"format": K.FORMAT, "realm": REALM, "version": 1, "trusted": None, "reason_sha256": "0" * 64,
      "at": "2026-11-06T20:00:00Z", "keys": [{"key": hx(K1), "origin": "keyclerk.example/log-1", "from_seq": 0, "to_seq": None}]}


def body(version, keys, trusted):
    return {"format": K.FORMAT, "realm": REALM, "version": version, "keys": keys, "trusted": trusted,
            "reason_sha256": "1" * 64, "at": "2026-11-06T21:00:00Z"}


def seal(doc, new_key, who=("eva", "owner"), accept=True):
    raw = K.canonical(doc)
    return {"bytes": base64.b64encode(raw).decode(), "trustees": trustee_sigs(K.FORMAT, raw, who),
            "accept": {"key": hx(new_key), "sig": new_key.sign(K.ACCEPT.encode() + b"\n" + raw).hex()} if accept else None}


def v2_body(b=10, witness=WITNESS, root=ROOT):
    keys = [{**V1["keys"][0], "to_seq": b}, {"key": hx(K2), "origin": "keyclerk.example/log-2", "from_seq": b, "to_seq": None}]
    return body(2, keys, {"note": note("keyclerk.example/log-1", b, K1, witness, root), "witness": WVKEY})


@pytest.fixture
def h1():
    return K.KeyHistory(V1)


def test_version_1_is_one_open_window(h1):
    assert h1.key_at(0) == hx(K1) and h1.key_at(10**9) == hx(K1)


def test_a_planned_rotation_switches_after_the_checkpoint_the_old_key_signed(h1):
    h2 = K.advance(h1, seal(v2_body(), K2), TS, WVKEY)
    assert h2.key_at(9) == hx(K1) and h2.key_at(10) == hx(K2)
    assert h2.checkpoint_key(10)["key"] == hx(K1)                      # the old key closes its own era
    assert h2.checkpoint_key(11)["origin"] == "keyclerk.example/log-2"
    assert list(K.dropped(h1, h2, 10)) == []                           # nothing held past the switch


def test_a_recovery_cuts_the_compromised_key_and_drops_its_links(h1):
    h2 = K.advance(h1, seal(v2_body(), K2), TS, WVKEY)
    keys = [h2.doc["keys"][0], {**h2.doc["keys"][1], "to_seq": 15},
            {"key": hx(K3), "origin": "keyclerk.example/log-3", "from_seq": 15, "to_seq": None}]
    h3 = K.advance(h2, seal(body(3, keys, {"note": note("keyclerk.example/log-2", 15, K2), "witness": WVKEY}), K3), TS, WVKEY)
    assert h3.key_at(14) == hx(K2) and h3.key_at(15) == hx(K3)
    assert list(K.dropped(h2, h3, 20)) == list(range(15, 20))          # what the stolen key signed after the checkpoint


def test_the_records_key_alone_cannot_name_its_successor(h1):
    """The holder of K1 writes a history to their own key: without the trustees it is nothing."""
    keys = [{**V1["keys"][0], "to_seq": 10}, {"key": hx(MALLORY), "origin": "evil/log", "from_seq": 10, "to_seq": None}]
    doc = body(2, keys, {"note": note("keyclerk.example/log-1", 10, K1), "witness": WVKEY})
    raw = K.canonical(doc)
    forged = {"bytes": base64.b64encode(raw).decode(), "trustees": [{"trustee_id": "eva", "sig": K1.sign(raw).hex()}],
              "accept": {"key": hx(MALLORY), "sig": MALLORY.sign(K.ACCEPT.encode() + b"\n" + raw).hex()}}
    with pytest.raises(K.HistoryRefused, match="not signed by the trustees"):
        K.advance(h1, forged, TS, WVKEY)


def test_one_trustee_role_is_not_enough(h1):
    with pytest.raises(K.HistoryRefused, match="one officer and one root"):
        K.advance(h1, seal(v2_body(), K2, who=("eva", "ingrid")), TS, WVKEY)


def test_a_skipped_version_is_refused(h1):
    doc = v2_body()
    doc["version"] = 3
    with pytest.raises(K.HistoryRefused, match="never skipped"):
        K.advance(h1, seal(doc, K2), TS, WVKEY)


def test_the_new_key_must_prove_possession(h1):
    with pytest.raises(K.HistoryRefused, match="proves possession"):
        K.advance(h1, seal(v2_body(), K2, accept=False), TS, WVKEY)
    s = seal(v2_body(), K2)
    s["accept"]["sig"] = K3.sign(b"x").hex()
    with pytest.raises(K.HistoryRefused, match="does not verify"):
        K.advance(h1, s, TS, WVKEY)


def test_earlier_windows_may_only_clip_at_the_switch(h1):
    doc = v2_body()
    doc["keys"][0]["from_seq"] = 0
    doc["keys"][0]["key"] = hx(MALLORY)                                # rewrite history before the switch
    with pytest.raises(K.HistoryRefused, match="not the pinned history's"):
        K.advance(h1, seal(doc, K2), TS, WVKEY)


def test_a_switch_never_reaches_into_a_retired_keys_era(h1):
    h2 = K.advance(h1, seal(v2_body(), K2), TS, WVKEY)
    keys = [{**V1["keys"][0], "to_seq": 5}, {"key": hx(K3), "origin": "keyclerk.example/log-3", "from_seq": 5, "to_seq": None}]
    doc = body(3, keys, {"note": note("keyclerk.example/log-1", 5, K1), "witness": WVKEY})
    with pytest.raises(K.HistoryRefused, match="before the current key's start"):
        K.advance(h2, seal(doc, K3), TS, WVKEY)


def test_a_key_or_an_origin_is_never_used_twice(h1):
    doc = v2_body()
    doc["keys"][1]["origin"] = "keyclerk.example/log-1"
    with pytest.raises(K.HistoryRefused, match="an origin is used once"):
        K.advance(h1, seal(doc, K2), TS, WVKEY)
    doc = v2_body()
    doc["keys"][1]["key"] = hx(K1)
    with pytest.raises(K.HistoryRefused, match="a key is used once"):
        K.advance(h1, seal(doc, K1), TS, WVKEY)


def test_the_switch_rests_on_a_countersigned_checkpoint_of_the_old_key_at_the_switch(h1):
    with pytest.raises(K.HistoryRefused, match="not countersigned"):
        K.advance(h1, seal(v2_body(witness=None), K2), TS, WVKEY)
    doc = v2_body()
    doc["trusted"]["note"] = note("keyclerk.example/log-1", 9, K1)
    with pytest.raises(K.HistoryRefused, match="size 9, the switch is at 10"):
        K.advance(h1, seal(doc, K2), TS, WVKEY)
    doc = v2_body()
    doc["trusted"]["note"] = note("keyclerk.example/log-1", 10, MALLORY)
    with pytest.raises(K.HistoryRefused, match="not signed by the key in force"):
        K.advance(h1, seal(doc, K2), TS, WVKEY)
    other = N.vkey("other.example", N.COSIGNATURE, N.raw_public(Ed25519PrivateKey.generate()))
    with pytest.raises(K.HistoryRefused, match="another witness than the one this verifier pins"):
        K.advance(h1, seal(v2_body(), K2), TS, other)


def test_bytes_that_are_not_canonical_are_refused(h1):
    s = seal(v2_body(), K2)
    s["bytes"] = base64.b64encode(K.canonical(v2_body()) + b" ").decode()
    with pytest.raises(K.HistoryRefused, match="not canonical"):
        K.advance(h1, s, TS, WVKEY)


def test_malformed_histories_are_refused_whole():
    for bad in ({}, {**V1, "version": 0}, {**V1, "keys": []},
                {**V1, "keys": [{**V1["keys"][0], "from_seq": 3}]},
                {**V1, "keys": [{**V1["keys"][0], "to_seq": 5}]},
                {**V1, "trusted": {"note": "x", "witness": "y"}}):
        assert K.check(copy.deepcopy(bad)), bad


def test_links_and_checkpoints_verify_against_the_key_in_force_at_their_position(h1):
    """The link format takes a history where it took one key: links before the switch by the old key, from it by the
    new one, and a checkpoint by the key that signed its last link."""
    from keyclerk.store import link as L
    h2 = K.advance(h1, seal(v2_body(b=2), K2), TS, WVKEY)
    entry = {"change_id": "C-t1", "action": "t", "outcome": "applied", "actor": None, "records": {}}
    head = None
    for seq, key in ((0, K1), (1, K1), (2, K2), (3, K2)):
        body = L.link_body(REALM, seq, head.hex() if head else L.ZERO, 1, "2026-11-06T21:00:00Z", [], entry)
        if seq == 2:                                                   # the old key past its window
            with pytest.raises(L.StoreRefused, match="not signed by the records key"):
                L.check_next(L.seal_body(K1, body), h2, REALM, seq, head, 1)
        _, head = L.check_next(L.seal_body(key, body), h2, REALM, seq, head, 1)
    cp_old = L.seal_checkpoint(K1, REALM, 2, ROOT, head, 1, "2026-11-06T21:00:00Z")
    assert L.open_checkpoint(cp_old, h2)["size"] == 2                  # the old key closes its era
    cp_new = L.seal_checkpoint(K2, REALM, 3, ROOT, head, 1, "2026-11-06T21:00:00Z")
    assert L.open_checkpoint(cp_new, h2)["size"] == 3
    with pytest.raises(L.StoreRefused):
        L.open_checkpoint(L.seal_checkpoint(K1, REALM, 3, ROOT, head, 1, "2026-11-06T21:00:00Z"), h2)


def _links(store, keys, start=0):
    from keyclerk.store import link as L
    entry = {"change_id": "C-t1", "action": "t", "outcome": "applied", "actor": None, "records": {}}
    for seq, key in enumerate(keys, start):
        head = store.head()
        body = L.link_body(REALM, seq, head.hex() if head else L.ZERO, 1, "2026-11-06T21:00:00Z", [], entry)
        store.append(L.seal_body(key, body))


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_a_store_adopts_a_rotation_and_takes_the_new_keys_links(h1, tmp_path, kind, monkeypatch):
    from keyclerk import trustees as T
    from keyclerk.store import link as L
    from keyclerk.store.memory import MemoryStore
    from keyclerk.store.sqlite import SqliteStore
    make = (lambda pin: MemoryStore(pin, REALM)) if kind == "memory" else (lambda pin: SqliteStore(tmp_path / "s.db", pin, REALM))
    store = make(hx(K1))
    _links(store, [K1, K1])
    h2 = K.advance(h1, seal(v2_body(b=2), K2), TS, WVKEY)
    with pytest.raises(L.StoreRefused, match="not signed by the records key"):
        _links(store, [K2], 2)                                         # before adopting, the new key counts for nothing
    store.adopt_history(h2)
    _links(store, [K2, K2], 2)
    assert store.size() == 4
    with pytest.raises(L.StoreRefused, match="not newer"):
        store.adopt_history(h2)
    if kind == "sqlite":
        store.close()
        with pytest.raises(L.StoreRefused, match="cannot verify"):    # its own meta is never trusted alone (N1)
            SqliteStore(tmp_path / "s.db", hx(K1), REALM)
        monkeypatch.setattr(K, "pinned", lambda: h1)                   # the operator's pins: version 1 and the trustees
        monkeypatch.setattr(T, "pinned", lambda: {"set": TS, "since": 0})
        again = SqliteStore(tmp_path / "s.db", hx(K1), REALM)          # version 2 rebuilt from the stored sealed chain
        try:
            assert again.pinned.version == 2
            _links(again, [K2], 4)
        finally:
            again.close()


def test_a_store_refuses_a_recovery_that_would_cut_links_it_holds(h1):
    from keyclerk.store import link as L
    from keyclerk.store.memory import MemoryStore
    h2 = K.advance(h1, seal(v2_body(b=2), K2), TS, WVKEY)
    store = MemoryStore(hx(K1), REALM)
    _links(store, [K1, K1])
    store.adopt_history(h2)
    _links(store, [K2, K2, K2], 2)                                     # K2 is stolen after link 3
    keys = [h2.doc["keys"][0], {**h2.doc["keys"][1], "to_seq": 4},
            {"key": hx(K3), "origin": "keyclerk.example/log-3", "from_seq": 4, "to_seq": None}]
    h3 = K.advance(h2, seal(body(3, keys, {"note": note("keyclerk.example/log-2", 4, K2), "witness": WVKEY}), K3), TS, WVKEY)
    with pytest.raises(L.StoreRefused, match="truncate to the switch first"):
        store.adopt_history(h3)


def test_a_history_from_another_genesis_key_is_refused(h1):
    from keyclerk.store import link as L
    from keyclerk.store.memory import MemoryStore
    store = MemoryStore(hx(MALLORY), REALM)
    with pytest.raises(L.StoreRefused, match="does not start from this store's records key"):
        store.adopt_history(K.advance(h1, seal(v2_body(b=2), K2), TS, WVKEY))


def test_a_store_adopts_the_history_its_process_pins(h1, tmp_path, monkeypatch):
    """records_keys: {history: FILE} in the configuration: a store opened there checks with that version."""
    from keyclerk.store.sqlite import SqliteStore
    store = SqliteStore(tmp_path / "s.db", hx(K1), REALM)
    _links(store, [K1, K1])
    store.close()
    h2 = K.advance(h1, seal(v2_body(b=2), K2), TS, WVKEY)
    monkeypatch.setattr(K, "pinned", lambda: h2)
    again = SqliteStore(tmp_path / "s.db", hx(K1), REALM)
    try:
        assert again.pinned.version == 2
        _links(again, [K2], 2)
    finally:
        again.close()
    monkeypatch.setattr(K, "pinned", lambda: None)
    third = SqliteStore(tmp_path / "s.db", hx(K1), REALM)                # without the pin only the genesis key counts
    try:
        assert third.pinned == hx(K1)
    finally:
        third.close()


def test_a_history_planted_in_a_stores_meta_is_never_trusted(h1, tmp_path, monkeypatch):
    """Review N1: whoever writes a store's state dir plants a history naming their own key: refused at open, with the
    pins or without them."""
    import json
    import sqlite3

    from keyclerk import trustees as T
    from keyclerk.store import link as L
    from keyclerk.store.sqlite import SqliteStore
    store = SqliteStore(tmp_path / "s.db", hx(K1), REALM)
    _links(store, [K1, K1])
    store.close()
    forged = {**V1, "version": 999, "keys": [{**V1["keys"][0], "key": hx(MALLORY)}]}
    planted = [{"bytes": base64.b64encode(K.canonical(forged)).decode(), "trustees": [], "accept": None}]
    db = sqlite3.connect(tmp_path / "s.db")
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('keys', ?)", (json.dumps(planted),))
    db.commit()
    db.close()
    with pytest.raises(L.StoreRefused, match="cannot verify"):
        SqliteStore(tmp_path / "s.db", hx(K1), REALM)
    monkeypatch.setattr(K, "pinned", lambda: h1)
    monkeypatch.setattr(T, "pinned", lambda: {"set": TS, "since": 0})
    with pytest.raises(L.StoreRefused, match="does not hold against the pins"):
        SqliteStore(tmp_path / "s.db", hx(K1), REALM)


def test_an_old_key_fork_before_the_switch_is_refused(h1):
    """Review N6: a follower that is new or behind takes the links before a switch under the old key; whoever stole it
    serves a fork of them. At the switch the log's root must be the one the history's trusted checkpoint names."""
    from keyclerk.store import link as L
    from keyclerk.store import note as N
    from keyclerk.store.memory import MemoryStore
    honest = MemoryStore(hx(K1), REALM)
    _links(honest, [K1, K1])
    text = N.checkpoint_text("keyclerk.example/log-1", 2, honest.root())
    trusted = text + "\n" + N.sign(text, "keyclerk.example/log-1", K1) + N.cosign(text, WNAME, WITNESS, 1_793_000_000)
    keys = [{**V1["keys"][0], "to_seq": 2},
            {"key": hx(K2), "origin": "keyclerk.example/log-2", "from_seq": 2, "to_seq": None}]
    h2 = K.advance(h1, seal(body(2, keys, {"note": trusted, "witness": WVKEY}), K2), TS, WVKEY)
    fresh = MemoryStore(h2, REALM)
    entry = {"change_id": "C-t9", "action": "forged", "outcome": "applied", "actor": None, "records": {}}
    b0 = L.link_body(REALM, 0, L.ZERO, 1, "2026-11-06T21:00:00Z", [], entry)
    fresh.append(L.seal_body(K1, b0))
    b1 = L.link_body(REALM, 1, fresh.head().hex(), 1, "2026-11-06T21:00:00Z", [], entry)
    with pytest.raises(L.StoreRefused, match="not the one the records-key history rests on"):
        fresh.append(L.seal_body(K1, b1))                              # a different second link: another root at 2
    again = MemoryStore(h2, REALM)
    for i in range(2):
        again.append(honest.link(i))                                   # the honest links reach the vouched root
    assert again.size() == 2


def test_n10_a_key_stolen_before_its_first_link_is_replaced_and_never_comes_back(h1):
    """0.29 review N10: a switch at the current key's own start replaces it before it signed anything; the replaced
    key stays out of every later version."""
    h2 = K.advance(h1, seal(v2_body(), K2), TS, WVKEY)
    keys = [{**V1["keys"][0], "to_seq": 10}, {"key": hx(K3), "origin": "keyclerk.example/log-3", "from_seq": 10,
                                              "to_seq": None}]
    h3 = K.advance(h2, seal(body(3, keys, {"note": note("keyclerk.example/log-1", 10, K1), "witness": WVKEY}), K3),
                   TS, WVKEY)
    assert h3.key_at(10) == hx(K3) and not K.dropped(h2, h3, 10) and list(K.dropped(h2, h3, 12)) == [10, 11]
    back = [{**V1["keys"][0], "to_seq": 10}, {"key": hx(K3), "origin": "keyclerk.example/log-3", "from_seq": 10,
                                              "to_seq": 20},
            {"key": hx(K2), "origin": "keyclerk.example/log-4", "from_seq": 20, "to_seq": None}]
    with pytest.raises(K.HistoryRefused, match="used once"):
        K.advance(h3, seal(body(4, back, {"note": note("keyclerk.example/log-3", 20, K3), "witness": WVKEY}), K2),
                  TS, WVKEY)
