"""Issue 28: signed snapshots of the change log (decision 0022 point 1). A store adopts a snapshot only with the
links up to it, checked as appends are; the state must hash to what the records key signed. Every test runs on both
stores."""
import random

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from keyclerk.store import open_store, replay as RP, snapshot as S
from keyclerk.store import link as L
from keyclerk.store.link import StoreRefused
from tests.test_store import AT, KEY, PUB, mem, nxt, put, view

pytestmark = pytest.mark.filterwarnings("ignore::ResourceWarning")


def _fresh(kind, tmp_path, name="adopted.db"):
    return open_store("memory:" if kind == "memory" else f"sqlite:{tmp_path / name}", PUB, "example")


def _log(seed=1, n=40):
    """A log with puts, overwrites, deletes and a head field, built in the reference store."""
    rnd, s, live = random.Random(seed), open_store("memory:", PUB, "example"), set()
    s.append(nxt(s, [{"op": "put", "kind": "head", "key": "realm", "record": {"value": "example"}}]))
    for _ in range(n):
        ops = {}
        for _ in range(rnd.randint(1, 4)):
            j = rnd.randrange(30)
            if j in live and rnd.random() < 0.3:
                ops[f"M-{j}"] = {"op": "del", "kind": "memberships", "key": f"M-{j}"}
                live.discard(j)
            else:
                ops[f"M-{j}"] = put("memberships", mem(j, anchor=rnd.choice(["idp:a", "idp:b", "idp:c"]),
                                                      group=rnd.choice(["g1", "g2"])))
                live.add(j)
        s.append(nxt(s, sorted(ops.values(), key=lambda o: o["key"])))
    return s


def _snap(src, tmp_path, size):
    """A snapshot of src as it stood at size links (the reference store replayed to there)."""
    part = RP.replay(src.links(0, size), PUB, "example")
    state = tmp_path / f"state-{size}.jsonl"
    return S.take(part.snapshot(), KEY, state, AT), state


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
@pytest.mark.parametrize("seed", range(3))
def test_a_store_from_a_snapshot_reads_as_one_built_from_the_genesis(kind, seed, tmp_path):
    src = _log(seed)
    sealed, state = _snap(src, tmp_path, 25)
    s = _fresh(kind, tmp_path)
    s.adopt(sealed, src.links(0, 25), state)
    for link in src.links(25):
        s.append(link)
    s.add_checkpoint(L.seal_checkpoint(KEY, "example", s.size(), s.root(), s.head(), 1, AT))
    RP.verify(s, PUB, "example")                                           # the whole chain still verifies
    assert view(s) == view(src)
    s.close()


def test_a_full_check_from_a_snapshot_agrees_with_one_from_the_genesis(tmp_path):
    src = _log(7, 60)
    sealed, state = _snap(src, tmp_path, 30)
    from_snap = S.replay_from(sealed, state, src.links(), PUB, "example")
    assert RP.records(from_snap) == RP.records(RP.replay(src.links(), PUB, "example"))


def _refused(kind, tmp_path, sealed, links, state, why):
    s = _fresh(kind, tmp_path, f"r-{abs(hash(why))}.db")
    with pytest.raises(StoreRefused, match=why):
        s.adopt(sealed, links, state)
    assert s.size() == 0 and s.count("memberships") == 0 and s.head() is None     # refused whole
    s.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_a_snapshot_not_signed_by_the_records_key_is_refused(kind, tmp_path):
    src = _log()
    part = RP.replay(src.links(0, 20), PUB, "example")
    sealed = S.take(part.snapshot(), Ed25519PrivateKey.generate(), tmp_path / "s", AT)
    _refused(kind, tmp_path, sealed, src.links(0, 20), tmp_path / "s", "not signed by the records key")


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_a_snapshot_of_another_history_is_refused(kind, tmp_path):
    src, other = _log(1), _log(2)                                         # same key, a different history
    sealed, state = _snap(other, tmp_path, 20)
    _refused(kind, tmp_path, sealed, src.links(0, 20), state, "head or root is not the log's")


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_a_state_file_that_is_not_the_signed_one_is_refused(kind, tmp_path):
    src = _log()
    sealed, state = _snap(src, tmp_path, 20)
    lines = state.read_bytes().splitlines(keepends=True)
    obj = E._parse(lines[1][:-1])
    obj["record"]["group"] = "g-admins"                                   # a record changed after signing
    lines[1] = E.canonical(obj) + b"\n"
    state.write_bytes(b"".join(lines))
    _refused(kind, tmp_path, sealed, src.links(0, 20), state, "not the one the snapshot was signed over")


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_a_signed_state_out_of_order_or_misfiled_is_refused(kind, tmp_path):
    """The hash is the signer's word; the shape is checked too, so a careless signer cannot plant a record under
    another key."""
    import hashlib
    src = _log()
    _, state = _snap(src, tmp_path, 20)
    lines = state.read_bytes().splitlines(keepends=True)
    for bad, why in ((lines[:1] + lines[2:3] + lines[1:2] + lines[3:], "out of order"),
                     (lines[:1] + [lines[1].replace(b'"key":"M-', b'"key":"X-', 1)] + lines[2:], "not the record's")):
        raw = b"".join(bad)
        p = tmp_path / f"bad-{why[:3]}"
        p.write_bytes(raw)
        part = RP.replay(src.links(0, 20), PUB, "example")
        body = E._parse(E._raw(S.take(part.snapshot(), KEY, tmp_path / "x", AT)["bytes"]))
        body["state"] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "records": len(bad)}
        _refused(kind, tmp_path, L._seal(KEY, S.FORMAT, body), src.links(0, 20), p, why)


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_too_few_or_too_many_links_or_a_used_store_are_refused(kind, tmp_path):
    src = _log()
    sealed, state = _snap(src, tmp_path, 20)
    _refused(kind, tmp_path, sealed, src.links(0, 19), state, "at 20 links, but 19 came")
    _refused(kind, tmp_path, sealed, src.links(0, 21), state, "more links than the snapshot's 20")
    s = _fresh(kind, tmp_path, "used.db")
    s.append(src.link(0))
    with pytest.raises(StoreRefused, match="only an empty store"):
        s.adopt(sealed, src.links(0, 20), state)
    s.close()


def test_a_snapshot_names_its_realm_and_comes_after_some_link(tmp_path):
    src = _log()
    sealed, _ = _snap(src, tmp_path, 10)
    with pytest.raises(StoreRefused, match="realm"):
        S.open_snapshot(sealed, PUB, "elsewhere")
    with pytest.raises(StoreRefused, match="empty log"):
        S.take(open_store("memory:", PUB, "example").snapshot(), KEY, tmp_path / "e", AT)
