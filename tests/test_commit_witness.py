# SPDX-License-Identifier: EUPL-1.2
"""Decision 0031 points 4, 5 and 9: the commit witness takes a checkpoint only with the links it adds, each checked as
a store checks an append, the root recomputed over every link it holds; one of two racing commits wins; it serves the
committed links to a standby, survives a restart, and is re-seeded from checked links, never from nothing."""
import json

import pytest

from keyclerk import commit_witness as C
from keyclerk import witness as W
from keyclerk.store import note as N
from keyclerk.store import open_store
from keyclerk.store.link import StoreRefused
from tests.test_store import KEY, PUB, mem, nxt, put

ORIGIN = "keyclerk.example/commit-test"
WKEY = W.Ed25519PrivateKey.from_private_bytes(b"c" * 32)


@pytest.fixture(autouse=True)
def _trustees_pinned(monkeypatch):
    """HA mode needs a pinned trustee set (0.29 review N8); these tests are not about trustee signatures, so links
    before a far-off position are taken as an upgraded deployment takes its older ones."""
    from keyclerk import trustees as T
    from tests.test_trustees import pinned_set
    ts = pinned_set("example")
    monkeypatch.setattr(T, "pinned", lambda: {"set": ts, "since": 10 ** 9})
    yield
    T.use(None)


def _store():
    s = open_store("memory:", PUB, "example")
    s.append(nxt(s, [{"op": "put", "kind": "head", "key": "realm", "record": {"value": "example"}}]))
    return s


def _grow(s, n, start=0):
    for i in range(start, start + n):
        s.append(nxt(s, [put("memberships", mem(i, anchor="idp:a", group="g1"))]))
    return s


def _note(s):
    text = N.checkpoint_text(ORIGIN, s.size(), s.root())
    return text + "\n" + N.sign(text, ORIGIN, KEY)


def _commit(w, old, links, note):
    return w.commit(json.dumps({"old": old, "links": links, "note": note}).encode())


def _witness(tmp_path):
    from tests.test_trustees import pinned_set
    return C.CommitWitness(WKEY, "witness.example/commit", tmp_path / "cw", [N.vkey(ORIGIN, N.LOG, N.raw_public(KEY))],
                           trustees=pinned_set("example"), trustees_since=10 ** 9)


def test_a_commit_carries_its_links_and_one_of_two_racing_commits_wins(tmp_path):
    w, s = _witness(tmp_path), _grow(_store(), 2)
    status, _, line = _commit(w, 0, list(s.links()), _note(s))
    assert status == 200 and N.verify(N.split(_note(s))[0], N.split(_note(s) + line.decode())[1], N.parse_vkey(w.vkey))
    a, b = _grow(_store(), 2), _grow(_store(), 2)
    a = _grow(a, 1, 10)                                                 # the active signs link 3
    b = _grow(b, 1, 20)                                                 # the standby signs another link 3
    assert _commit(w, 3, list(a.links(3)), _note(a))[0] == 200
    status, ctype, body = _commit(w, 3, list(b.links(3)), _note(b))
    assert (status, ctype, body) == (409, W.SIZE_TYPE, b"4\n")            # it lost: the witness holds 4
    assert _commit(w, 4, [], _note(b))[0] == 422                          # its tree is not the committed one
    assert '"kind": "inconsistent"' in (w.state / "evidence.jsonl").read_text()


def test_a_checkpoint_not_matching_its_links_is_refused(tmp_path):
    w, s = _witness(tmp_path), _grow(_store(), 2)
    other = _grow(_store(), 2, 50)
    assert _commit(w, 0, list(s.links()), _note(other))[0] == 422          # the root of another tree
    assert _commit(w, 0, list(s.links())[:2], _note(s))[0] == 422          # a link short of the checkpoint
    forged = [dict(x) for x in s.links()]
    forged[1] = dict(forged[0])                                            # a link that does not follow
    assert _commit(w, 0, forged, _note(s))[0] == 422
    assert w.add_checkpoint(W.request_body(0, [], _note(s)))[0] == 400     # never a bare checkpoint


def test_a_lost_answer_is_asked_again_and_confirmed(tmp_path):
    w, s = _witness(tmp_path), _grow(_store(), 2)
    assert _commit(w, 0, list(s.links()), _note(s))[0] == 200
    status, _, line = _commit(w, s.size(), [], _note(s))                   # the same checkpoint, no links
    assert status == 200 and line.startswith(N.DASH.encode())


def test_the_committed_links_serve_a_standby_and_survive_a_restart(tmp_path):
    w, s = _witness(tmp_path), _grow(_store(), 4)
    assert _commit(w, 0, list(s.links()), _note(s))[0] == 200
    status, _, body = w.links(W.origin_hash(ORIGIN), 2, 10)
    got = json.loads(body)
    assert status == 200 and got["size"] == 5 and got["links"] == list(s.links(2))
    with open(tmp_path / "cw" / "commit" / W.origin_hash(ORIGIN) / "links.jsonl", "a") as f:
        f.write(json.dumps(next(_grow(_store(), 5, 90).links(5))) + "\n")   # written, never answered (a crash)
    again = _witness(tmp_path)
    assert again.commits[ORIGIN].size == 5
    assert again.links(W.origin_hash(ORIGIN), 0, 500)[0] == 200
    t = _grow(s, 1, 30)
    assert _commit(again, 5, list(t.links(5)), _note(t))[0] == 200         # it goes on from the committed head


def test_a_reseed_starts_from_checked_links_never_from_nothing(tmp_path):
    w, s = _witness(tmp_path), _grow(_store(), 3)
    assert _commit(w, 0, list(s.links()), _note(s))[0] == 200
    seed = tmp_path / "seed.jsonl"
    seed.write_text("".join(json.dumps(x) + "\n" for x in s.links(0, 3)))
    seed_store = _grow(_store(), 2)
    out = C.reseed(tmp_path / "cw", ORIGIN, PUB, seed, "witness-owner", "the witness host was lost", lambda: 1_800_000_000,
                   _note(seed_store), WKEY, "witness.example/commit")
    assert out["size"] == 3
    again = _witness(tmp_path)
    assert again.commits[ORIGIN].size == 3 and again.checkpoint(W.origin_hash(ORIGIN))[0] == 200     # countersigned
    with pytest.raises(ValueError, match="for the seed"):
        C.reseed(tmp_path / "cw", ORIGIN, PUB, seed, "x", "y", lambda: 1, _note(_grow(_store(), 1)), WKEY, "w")
    t = _grow(_store(), 2)
    t = _grow(t, 1, 70)
    assert _commit(again, 3, list(t.links(3)), _note(t))[0] == 200
    (tmp_path / "empty.jsonl").write_text("")
    with pytest.raises(ValueError, match="never from nothing"):
        C.reseed(tmp_path / "cw", ORIGIN, PUB, tmp_path / "empty.jsonl", "x", "y", lambda: 1, "", WKEY, "w")
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps(next(s.links(1))) + "\n")                     # not from the genesis
    with pytest.raises(StoreRefused, match="link 1 where link 0 comes next"):
        C.reseed(tmp_path / "cw", ORIGIN, PUB, bad, "x", "y", lambda: 1, "", WKEY, "w")


def test_the_commit_witness_answers_over_http(tmp_path):
    import threading
    import urllib.request
    w, s = _witness(tmp_path), _grow(_store(), 2)
    srv = W.serve(w, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        body = json.dumps({"old": 0, "links": list(s.links()), "note": _note(s)}).encode()
        assert W.http("POST", base + "/commit", body, 10)[0] == 200
        status, _, raw = W.http("GET", f"{base}/{W.origin_hash(ORIGIN)}/links?start=1&limit=5", None, 10)
        assert status == 200 and json.loads(raw)["size"] == 3
        assert W.http("GET", f"{base}/{W.origin_hash(ORIGIN)}/checkpoint", None, 10)[0] == 200
        assert W.http("POST", base + "/add-checkpoint", W.request_body(0, [], _note(s)), 10)[0] == 400
    finally:
        srv.shutdown()
        srv.server_close()
