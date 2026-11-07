# SPDX-License-Identifier: EUPL-1.2
"""The commit witness follows the records-key history (#41, F3): it adopts a newer version only on the trustee set it
pins and its own countersignature, takes the new key's links and checkpoints under the new origin into the same log,
refuses a checkpoint under an origin the history does not have in force, and keeps the history across a restart."""
import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import commit_witness as C
from keyclerk import records_keys as K
from keyclerk import trustees as T
from keyclerk.store import note as N
from keyclerk.store import open_store
from tests.test_store import KEY, PUB, mem, nxt, put
from tests.test_trustees import pinned_set, trustee_sigs

O1, O2 = "keyclerk.example/rot-1", "keyclerk.example/rot-2"
WKEY = Ed25519PrivateKey.from_private_bytes(b"k" * 32)
WNAME = "witness.example/rot"
K2 = Ed25519PrivateKey.generate()
TS = pinned_set("example")
V1 = K.KeyHistory({"format": K.FORMAT, "realm": "example", "version": 1, "trusted": None, "reason_sha256": "0" * 64,
                   "at": "2026-11-06T20:00:00Z", "keys": [{"key": PUB, "origin": O1, "from_seq": 0, "to_seq": None}]})


@pytest.fixture(autouse=True)
def _unpin():
    yield
    T.use(None)                                    # the witness pins its set for the whole process


def _note(origin, s, key):
    text = N.checkpoint_text(origin, s.size(), s.root())
    return text + "\n" + N.sign(text, origin, key)


def _commit(w, old, links, note):
    return w.commit(json.dumps({"old": old, "links": links, "note": note}).encode())


def _witness(tmp_path, trustees=TS):
    return C.CommitWitness(WKEY, WNAME, tmp_path / "cw", [N.vkey(O1, N.LOG, N.raw_public(KEY))], trustees=trustees,
                           histories=[V1])


def _grow(s, n, key):
    out = []
    for _ in range(n):
        link = nxt(s, [put("memberships", mem(s.size(), anchor="idp:a", group="g1"))], key=key)
        s.append(link)
        out.append(link)
    return out


def _v2(w, s):
    """Version 2, switching at the log's size, resting on the witness's own countersignature there."""
    b = s.size()
    cosigned = json.loads((w._file(O1)).read_text(encoding="utf-8"))["note"]
    doc = {"format": K.FORMAT, "realm": "example", "version": 2, "reason_sha256": "1" * 64, "at": "2026-11-06T21:00:00Z",
           "keys": [{"key": PUB, "origin": O1, "from_seq": 0, "to_seq": b},
                    {"key": K2.public_key().public_bytes_raw().hex(), "origin": O2, "from_seq": b, "to_seq": None}],
           "trusted": {"note": cosigned, "witness": w.vkey}}
    raw = K.canonical(doc)
    return {"bytes": base64.b64encode(raw).decode(), "trustees": trustee_sigs(K.FORMAT, raw),
            "accept": {"key": doc["keys"][1]["key"], "sig": K2.sign(K.ACCEPT.encode() + b"\n" + raw).hex()}}


def _started(tmp_path):
    w = _witness(tmp_path)
    s = open_store("memory:", V1, "example")
    links = _grow(s, 3, KEY)
    assert _commit(w, 0, links, _note(O1, s, KEY))[0] == 200
    return w, s


def test_the_witness_adopts_a_rotation_and_takes_the_new_keys_links_under_the_new_origin(tmp_path):
    w, s = _started(tmp_path)
    sealed = _v2(w, s)
    status, _, why = w.adopt_keys(json.dumps({"origin": O1, "sealed": sealed}).encode())
    assert status == 200, why
    s.adopt_history(K.advance(V1, sealed, TS, w.vkey))
    links = _grow(s, 2, K2)
    status, _, why = _commit(w, 3, links, _note(O2, s, K2))
    assert status == 200, why
    assert w.commits[O1].size == 5                                     # one log, two origins


def test_a_checkpoint_under_an_origin_not_in_force_is_refused(tmp_path):
    w, s = _started(tmp_path)
    sealed = _v2(w, s)
    w.adopt_keys(json.dumps({"origin": O1, "sealed": sealed}).encode())
    s.adopt_history(K.advance(V1, sealed, TS, w.vkey))
    links = _grow(s, 1, K2)
    status, _, why = _commit(w, 3, links, _note(O1, s, KEY))           # the old key and origin past the switch
    assert status == 403 and b"signed under" in why


def test_the_witness_keeps_the_history_across_a_restart(tmp_path):
    w, s = _started(tmp_path)
    sealed = _v2(w, s)
    w.adopt_keys(json.dumps({"origin": O1, "sealed": sealed}).encode())
    s.adopt_history(K.advance(V1, sealed, TS, w.vkey))
    again = _witness(tmp_path)
    assert again.commits[O1].pinned.version == 2
    links = _grow(s, 1, K2)
    assert _commit(again, 3, links, _note(O2, s, K2))[0] == 200


def test_without_a_pinned_trustee_set_the_witness_does_not_start(tmp_path):
    """Review N8: a commit witness without the trustee set it pins would let the records key decide HA changes."""
    with pytest.raises(ValueError, match="needs the trustee set"):
        _witness(tmp_path, trustees=None)


def test_a_history_by_one_trustee_role_is_refused(tmp_path):
    w, s = _started(tmp_path)
    sealed = _v2(w, s)
    raw = base64.b64decode(sealed["bytes"])
    sealed["trustees"] = trustee_sigs(K.FORMAT, raw, ("eva", "ingrid"))
    status, _, why = w.adopt_keys(json.dumps({"origin": O1, "sealed": sealed}).encode())
    assert status == 422 and b"does not hold" in why


def test_a_keys_file_planted_in_the_witness_state_is_never_trusted(tmp_path):
    """Review N2: whoever writes the witness's state dir plants a history; without the pins it refuses to start, and with
    them the plant does not hold."""
    w, s = _started(tmp_path)
    forged = {**V1.doc, "version": 9, "keys": [{**V1.doc["keys"][0], "key": K2.public_key().public_bytes_raw().hex()}]}
    planted = [{"bytes": base64.b64encode(K.canonical(forged)).decode(), "trustees": [], "accept": None}]
    (w.commits[O1].d / "keys.json").write_text(json.dumps(planted), encoding="utf-8")
    with pytest.raises(ValueError, match="cannot verify"):
        C.CommitWitness(WKEY, WNAME, tmp_path / "cw", [N.vkey(O1, N.LOG, N.raw_public(KEY))], trustees=TS)
    with pytest.raises(K.HistoryRefused):
        _witness(tmp_path)


def test_a_history_cannot_take_another_logs_origin(tmp_path):
    """Review N3: a history whose new window names an origin another witnessed log holds is refused."""
    other = Ed25519PrivateKey.generate()
    w = C.CommitWitness(WKEY, WNAME, tmp_path / "cw", [N.vkey(O1, N.LOG, N.raw_public(KEY)),
                                                       N.vkey(O2, N.LOG, N.raw_public(other))], trustees=TS, histories=[V1])
    s = open_store("memory:", V1, "example")
    _commit(w, 0, _grow(s, 3, KEY), _note(O1, s, KEY))
    status, _, why = w.adopt_keys(json.dumps({"origin": O1, "sealed": _v2(w, s)}).encode())   # v2 names O2
    assert status == 409 and b"another log" in why


def test_trustees_since_lets_an_existing_witness_pin_them(tmp_path):
    """Review N7: links before `since` were written before trustee signatures existed."""
    _witness(tmp_path)
    T.use(None)                                    # a restart: a new process pins the set again, with since
    C.CommitWitness(WKEY, WNAME, tmp_path / "cw", [N.vkey(O1, N.LOG, N.raw_public(KEY))], trustees=TS,
                    histories=[V1], trustees_since=10)
    assert T.pinned()["since"] == 10


def test_a_rotated_log_is_reseeded_with_its_history(tmp_path):
    """0.29 review N9: a reseed took one key, so a log past a records-key rotation could not be reseeded (or lost its
    history). It takes the log's pinned history and the trustee set, checks every link and the seed checkpoint under
    the key in force there, and the restarted witness holds the history."""
    w, s = _started(tmp_path)
    sealed = _v2(w, s)
    w.adopt_keys(json.dumps({"origin": O1, "sealed": sealed}).encode())
    v2 = K.advance(V1, sealed, TS, w.vkey)
    s.adopt_history(v2)
    _grow(s, 2, K2)
    seed = tmp_path / "seed.jsonl"
    seed.write_text("".join(json.dumps(x) + "\n" for x in s.links(0, 5)))
    note = _note(O2, s, K2)
    with pytest.raises(ValueError, match="--records-keys"):
        C.reseed(tmp_path / "cw2", O1, PUB, seed, "owner", "host lost", lambda: 1_800_000_000, note, WKEY, WNAME)
    out = C.reseed(tmp_path / "cw2", O1, PUB, seed, "owner", "host lost", lambda: 1_800_000_000, note, WKEY, WNAME,
                   history=v2, trustees=TS)
    assert out["size"] == 5
    again = C.CommitWitness(WKEY, WNAME, tmp_path / "cw2", [N.vkey(O1, N.LOG, N.raw_public(KEY))], trustees=TS,
                            histories=[v2])
    assert again.commits[O1].size == 5 and again.commits[O1].pinned.version == 2
