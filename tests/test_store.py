"""Decision 0022 S1: the store core. Every test runs on both stores: the in-memory reference store keeps the interface
honest, so what the SQLite store does is what the interface says, not what SQLite happens to do."""
import base64
import random
import sqlite3
from pathlib import PurePosixPath

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from keyclerk.store import INDEXES, link as L, open_store, replay as RP, sqlite as SQ
from keyclerk.store.link import StoreRefused

KEY = Ed25519PrivateKey.generate()
PUB = E.public_hex(KEY)
AT = "2026-10-24T12:00:00Z"


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    s = open_store("memory:" if request.param == "memory" else f"sqlite:{tmp_path / 'store.db'}", PUB, "example")
    yield s
    s.close()


def both(tmp_path):
    return [open_store("memory:", PUB, "example"), open_store(f"sqlite:{tmp_path / 'both.db'}", PUB, "example")]


def nxt(s, ops, fence=1, key=KEY, entry=None, **over):
    """The next link for a store: seq and prev from its own head."""
    h = s.head()
    args = {"realm": "example", "seq": s.size(), "prev": h.hex() if h else L.ZERO, "fence": fence, "at": AT,
            "ops": ops, "entry": entry or {"action": "test"}, **over}
    return L.seal_link(key, **args)


def put(kind, rec, key=None):
    return {"op": "put", "kind": kind, "key": key or L.record_key(kind, rec), "record": rec}


def mem(i, anchor="idp:a", group="g1", start="2026-01-01T00:00:00Z", end=None):
    r = {"membership_id": f"M-{i}", "anchor": anchor, "group": group, "start": start}
    return {**r, "end": end} if end else r


def view(s):
    """Everything a reader can see, for comparing two stores."""
    out = {"size": s.size(), "head": s.head(), "root": s.root(), "records": RP.records(s),
           "scan": {k: list(s.scan(k)) for k in L.LOG_KINDS}, "count": {k: s.count(k) for k in L.LOG_KINDS}}
    for field, values in (("member.anchor", ["idp:a", "idp:b"]), ("group", ["g1"]), ("start_day", ["2026-03-01"]),
                          ("anchor", ["idp:c"]), ("by", ["idp:a"]), ("member.rule", ["yes"])):
        out[f"find {field}"] = s.find("memberships", field, values)
    out["get_many"] = s.get_many("memberships", [f"M-{i}" for i in range(0, 40, 3)] + ["M-none"])
    for ix in INDEXES:
        for lo, hi in (("idp:a", None), ("g1", None), ("2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z"), ("", "~")):
            out[f"{ix} {lo} {hi}"] = list(s.range("memberships", ix, lo, hi))
    return out


# --- the same links give the same state in both stores ----------------------------------------------------------------

@pytest.mark.parametrize("seed", range(6))
def test_both_stores_give_identical_results_for_the_same_links(tmp_path, seed):
    rnd = random.Random(seed)
    stores = both(tmp_path)
    live: set[str] = set()
    for _ in range(25):
        ops = {}
        for _ in range(rnd.randint(1, 6)):
            i = rnd.randint(0, 30)
            key = f"M-{i}"
            if key in live and key not in ops and rnd.random() < 0.3:
                ops[key] = {"op": "del", "kind": "memberships", "key": key}
            elif key not in ops:
                month = rnd.randint(1, 12)
                rec = mem(i, anchor=rnd.choice(["idp:a", "idp:b", "idp:c"]), group=rnd.choice(["g1", "g2"]),
                          start=f"2026-{month:02d}-01T00:00:00Z")
                if rnd.random() < 0.2:
                    rec["anchor"] = 7                       # not text: in no index, in either store
                ops[key] = put("memberships", rec)
        if rnd.random() < 0.3:
            ops["~head"] = put("head", {"value": rnd.choice(["home-a", "home-b"])}, "home")
        sealed = nxt(stores[0], list(ops.values()))
        for s in stores:
            s.append(sealed)
        live = {k for k, _ in stores[0].scan("memberships")}
    a, b = (view(s) for s in stores)
    assert a == b
    assert RP.records(RP.replay(stores[1].links(), PUB, "example")) == a["records"]
    for s in stores:
        s.close()


def test_records_come_back_in_todays_shape(store):
    store.append(nxt(store, [put("head", {"value": "example"}, "realm"), put("groups", {"group_id": "g1"}),
                             put("memberships", mem(1)), put("persons", {"person": "idp:a"})]))
    doc = RP.records(store)
    assert doc["realm"] == "example" and doc["revision"] == 1
    assert doc["groups"] == [{"group_id": "g1"}] and doc["memberships"] == [mem(1)]
    assert doc["grants"] == [] and doc["revocations"] == [] and doc["suspensions"] == []
    assert "leases" not in doc                          # an optional kind with nothing in it is left out, as records.load does


def test_a_log_that_starts_empty_counts_revisions_from_one(store):
    store.append(nxt(store, [put("head", {"value": "example"}, "realm")]))
    store.append(nxt(store, [put("groups", {"group_id": "g1"})]))
    assert RP.records(store)["revision"] == 2 and store.migration() is None
    with pytest.raises(StoreRefused, match="the migration ended at link 0"):
        store.append(nxt(store, [put("groups", {"group_id": "g2"})], migrate={"part": 2, "parts": 2}))


# --- refused links: nothing applied -----------------------------------------------------------------------------------

def _three(store):
    for i in range(3):
        store.append(nxt(store, [put("memberships", mem(i))]))


def test_a_tampered_link_is_refused_and_nothing_changes(store):
    _three(store)
    before = view(store)
    good = nxt(store, [put("memberships", mem(9))])
    raw = base64.b64decode(good["bytes"])
    tampered = [
        {**good, "bytes": base64.b64encode(raw.replace(b"M-9", b"M-8")).decode()},
        {**good, "signature": ("0" if good["signature"][0] != "0" else "1") + good["signature"][1:]},
        nxt(store, [put("memberships", mem(9))], key=Ed25519PrivateKey.generate()),
        {**good, "key": PUB},
    ]
    for t in tampered:
        with pytest.raises(StoreRefused):
            store.append(t)
    assert view(store) == before


def test_a_reordered_or_replayed_link_is_refused(store):
    l0 = nxt(store, [put("memberships", mem(0))])
    store.append(l0)
    l1 = nxt(store, [put("memberships", mem(1))])
    h1 = L.open_link(l1, PUB)[1]
    l2 = L.seal_link(KEY, "example", 2, h1.hex(), 1, AT, [put("memberships", mem(2))], {"action": "test"})
    with pytest.raises(StoreRefused, match="link 2 where link 1 comes next"):
        store.append(l2)
    with pytest.raises(StoreRefused, match="link 0 where link 1"):
        store.append(l0)
    with pytest.raises(StoreRefused, match="does not follow the head"):
        store.append(L.seal_link(KEY, "example", 1, "ab" * 32, 1, AT, [put("memberships", mem(1))], {"action": "test"}))
    store.append(l1)
    store.append(l2)
    assert store.size() == 3


def test_a_lower_fence_is_refused_and_a_higher_one_holds(store):
    store.append(nxt(store, [put("memberships", mem(0))], fence=2))
    with pytest.raises(StoreRefused, match="fence 1 after fence 2"):
        store.append(nxt(store, [put("memberships", mem(1))], fence=1))
    store.append(nxt(store, [put("memberships", mem(1))], fence=3))
    assert store.size() == 2


def test_a_link_applies_whole_or_not_at_all(store):
    store.append(nxt(store, [put("memberships", mem(0))]))
    with pytest.raises(StoreRefused, match="no such record"):
        store.append(nxt(store, [put("groups", {"group_id": "a"}), {"op": "del", "kind": "memberships", "key": "M-7"}]))
    assert store.get("groups", "a") is None and store.size() == 1
    store.append(nxt(store, [{"op": "del", "kind": "memberships", "key": "M-0"}]))
    assert store.get("memberships", "M-0") is None


@pytest.mark.parametrize("ops,why", [
    ([{"op": "put", "kind": "visits", "key": "V-1", "record": {"visit_id": "V-1"}}], "outside the log"),
    ([put("approval_proofs", {"records": ["M-1"], "by": "idp:a", "token": "t", "sha256": "0" * 64}, "0" * 64)], "never the token"),
    ([put("groups", {"group_id": "a"}, "b")], "not the record's own"),
    ([put("head", {"value": 1}, "revision")], "not a head field"),
    ([put("nonsense", {"x": 1}, "x")], "not a kind"),
])
def test_what_never_enters_the_log(ops, why):
    with pytest.raises(StoreRefused, match=why):
        L.seal_link(KEY, "example", 0, L.ZERO, 1, AT, ops, {"action": "test"})


# --- checkpoints ------------------------------------------------------------------------------------------------------

def test_a_checkpoint_verifies_and_a_wrong_one_is_refused(store):
    _three(store)
    size, root, head = store.size(), store.root(), store.head()
    for bad, why in ((L.seal_checkpoint(KEY, "example", size, b"\x11" * 32, head, 1, AT), "root or head"),
                     (L.seal_checkpoint(KEY, "example", size - 1, root, head, 1, AT), "the log holds 3"),
                     (L.seal_checkpoint(Ed25519PrivateKey.generate(), "example", size, root, head, 1, AT), "not signed"),
                     (L.seal_checkpoint(KEY, "elsewhere", size, root, head, 1, AT), "realm")):
        with pytest.raises(StoreRefused, match=why):
            store.add_checkpoint(bad)
    assert store.checkpoint() is None
    cp = L.seal_checkpoint(KEY, "example", size, root, head, 1, AT)
    store.add_checkpoint(cp)
    store.add_checkpoint(cp)                              # the same one again: kept once
    with pytest.raises(StoreRefused, match="already kept"):
        store.add_checkpoint(L.seal_checkpoint(KEY, "example", size, root, head, 1, "2026-10-25T00:00:00Z"))
    assert store.checkpoint() == cp
    assert L.open_checkpoint(store.checkpoint(), PUB)["root"] == root.hex()
    store.append(nxt(store, [put("memberships", mem(5))]))
    with pytest.raises(StoreRefused):
        store.add_checkpoint(cp)                          # it no longer states this log


# --- the side table: not in the log -----------------------------------------------------------------------------------

def test_side_records_stay_out_of_the_chain_and_can_be_erased(store):
    token = "eyJ.token.sig"
    proof = L.proof_record({"records": ["M-1"], "by": "idp:a", "token": token})
    store.append(nxt(store, [put("approval_proofs", proof)]))
    root = store.root()
    store.side_put("proof_tokens", proof["sha256"], {"token": token})
    store.side_put("visits", "V-1", {"visit_id": "V-1", "host": "idp:a"})
    assert store.root() == root and store.size() == 1     # the chain does not move
    doc = RP.records(store)
    assert doc["approval_proofs"] == [{"records": ["M-1"], "by": "idp:a", "token": token}]
    assert doc["visits"] == [{"visit_id": "V-1", "host": "idp:a"}]
    store.side_delete("proof_tokens", proof["sha256"])
    store.side_delete("visits", "V-1")
    doc = RP.records(store)
    assert doc["approval_proofs"] == [proof] and "visits" not in doc     # erased: the hash stays, the chain verifies
    assert RP.records(RP.replay(store.links(), PUB, "example"))["approval_proofs"] == [proof]
    with pytest.raises(StoreRefused, match="under its sha256"):
        store.side_put("proof_tokens", "0" * 64, {"token": token})
    with pytest.raises(StoreRefused, match="not the record's visit_id"):
        store.side_put("visits", "V-2", {"visit_id": "V-3"})
    with pytest.raises(StoreRefused, match="not a kind kept outside"):
        store.side_put("memberships", "M-1", mem(1))


# --- snapshots --------------------------------------------------------------------------------------------------------

def test_a_snapshot_does_not_move_and_cannot_be_written(store):
    _three(store)
    store.side_put("visits", "V-1", {"visit_id": "V-1"})
    snap = store.snapshot()
    before = view(snap)
    store.append(nxt(store, [put("memberships", mem(7))]))
    store.side_put("visits", "V-2", {"visit_id": "V-2"})
    assert view(snap) == before and snap.size() == 3
    assert [k for k, _ in snap.side_scan("visits")] == ["V-1"]
    with pytest.raises(StoreRefused, match="read only"):
        snap.append(nxt(snap, [put("memberships", mem(8))]))
    with pytest.raises(StoreRefused, match="read only"):
        snap.side_put("visits", "V-3", {"visit_id": "V-3"})
    snap.close()


def test_a_sqlite_snapshot_is_its_own_file_and_goes_when_closed(tmp_path):
    s = open_store(f"sqlite:{tmp_path / 'store.db'}", PUB, "example")
    _three(s)
    snap = s.snapshot()
    files = {p.name for p in tmp_path.iterdir()}
    assert any(n.startswith(".snapshot-") for n in files)
    snap.close()
    assert not any(p.name.startswith(".snapshot-") for p in tmp_path.iterdir())
    s.close()


# --- the SQLite store at open -----------------------------------------------------------------------------------------

def test_a_sqlite_store_reopens_with_its_key_and_refuses_another(tmp_path):
    p = tmp_path / "store.db"
    s = open_store(f"sqlite:{p}", PUB, "example")
    _three(s)
    root = s.root()
    s.close()
    s = open_store(f"sqlite:{p}", PUB, "example")
    assert s.size() == 3 and s.root() == root
    s.append(nxt(s, [put("memberships", mem(4))]))
    s.close()
    with pytest.raises(StoreRefused, match="another records key"):
        open_store(f"sqlite:{p}", E.public_hex(Ed25519PrivateKey.generate()), "example")
    with pytest.raises(StoreRefused, match="holds realm example"):
        open_store(f"sqlite:{p}", PUB, "elsewhere")
    other = tmp_path / "other.db"
    sqlite3.connect(other).execute("CREATE TABLE t (x)").connection.close()
    with pytest.raises(StoreRefused, match="not a KeyClerk store"):
        open_store(f"sqlite:{other}", PUB, "example")


def test_the_generated_columns_are_the_records_own(tmp_path):
    """The database computes the index columns from the JSON, so they cannot drift from the record."""
    s = open_store(f"sqlite:{tmp_path / 'store.db'}", PUB, "example")
    s.append(nxt(s, [put("memberships", mem(1, anchor="idp:x", group="g9", end="2027-01-01T00:00:00Z"))]))
    row = s._db.execute("SELECT anchor, grp, t_start, t_end FROM records WHERE key = 'M-1'").fetchone()
    assert row == ("idp:x", "g9", "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
    for ix, col in SQ.COLUMNS.items():
        plan = " ".join(r[-1] for r in s._db.execute(
            f"EXPLAIN QUERY PLAN SELECT key FROM records INDEXED BY records_{col} WHERE kind = 'memberships' "
            f"AND {col} >= 'a' AND {col} < 'z' ORDER BY {col}, key"))
        assert f"records_{col}" in plan and "TEMP B-TREE" not in plan, (ix, plan)
    assert s._db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    s.close()


def test_an_old_sqlite_is_refused_with_what_to_do(tmp_path, monkeypatch):
    monkeypatch.setattr(SQ.sqlite3, "sqlite_version_info", (3, 37, 2))
    monkeypatch.setattr(SQ.sqlite3, "sqlite_version", "3.37.2")
    with pytest.raises(StoreRefused, match=r"3\.37\.2; the store needs 3\.38 or later.*newer SQLite"):
        open_store(f"sqlite:{tmp_path / 'store.db'}", PUB, "example")


def test_a_network_or_sync_filesystem_is_refused_with_what_to_do(tmp_path, monkeypatch):
    monkeypatch.setattr(SQ, "filesystem", lambda p: ("GoogleDriveFS", "G" ":\\ is a GoogleDriveFS volume, not a local NTFS or ReFS one"))
    with pytest.raises(StoreRefused, match=r"on GoogleDriveFS: .*one host and a local disk.*Put the store on"):
        open_store(f"sqlite:{tmp_path / 'store.db'}", PUB, "example")
    assert not (tmp_path / "store.db").exists()


def test_the_local_disk_the_tests_run_on_is_accepted(tmp_path):
    assert SQ.filesystem(tmp_path)[1] is None


def test_linux_mounts_are_read_from_mountinfo():
    info = "\n".join([
        "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw",
        "40 22 0:35 / /mnt/share rw,relatime shared:2 - nfs4 srv:/export rw",
        "41 22 0:36 / /srv/me/My\\040Drive rw - fuse.rclone gdrive: rw",
        "42 22 0:37 / /data rw - xfs /dev/sdb1 rw",
    ])
    assert SQ._linux(PurePosixPath("/data/keyclerk"), info) == ("xfs", None)
    assert SQ._linux(PurePosixPath("/srv/keyclerk"), info) == ("ext4", None)
    assert SQ._linux(PurePosixPath("/mnt/share/keyclerk"), info)[0] == "nfs4" and SQ._linux(PurePosixPath("/mnt/share/x"), info)[1]
    assert SQ._linux(PurePosixPath("/srv/me/My Drive/kc"), info)[1] == "/srv/me/My Drive is a fuse.rclone filesystem"
    assert SQ._linux(PurePosixPath("/mnt/shared"), info) == ("ext4", None)     # a prefix of a name is not its mount
